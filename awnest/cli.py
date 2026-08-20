"""awnest CLI.

    awnest challenge -n 3                       issue a challenge set (JSON)
    awnest judge --url http://127.0.0.1:8080 --model my-model --answers a.json
    awnest mint   --audience checkout --subject u_42 --verdict human --score 80
    awnest verify TOKEN --audience checkout
    awnest gate   TOKEN --audience checkout --subject u_42
    awnest --self-test

The signing secret comes from --secret or AWNEST_SECRET, and the judge origin from
--url. Neither is guessed: a gate that falls back to a default key trusts whoever
knows the default, and a judge that falls back to a default endpoint posts a
stranger's childhood memory to a host nobody chose.

Exit codes:  0 admitted / ok      1 refused or broke      2 you asked wrongly
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Optional

from awnest.attest import (
    ATTESTATION_FIELDS,
    AttestationError,
    HmacKey,
    MemorySeen,
    mint,
    payload_for,
    verify,
)
from awnest.audience import KINDS, audience
from awnest.audience import parse as parse_audience
from awnest.challenge import (
    CATEGORIES,
    CHALLENGES,
    JUDGEMENT_FIELDS,
    check_answers,
    judge_prompt,
    parse_judgement,
    select,
)
from awnest.client import SESSION_HEADER, SUBMIT_FIELDS, submit_body
from awnest.commit import (
    TRAILER,
    attest_commit,
    find_trailer,
    repo_audience,
    trailer_line,
    tree_context,
    verify_commit,
)
from awnest.nest import Nest, NotAdmitted
from awnest.verdict import (
    DECLARED_AGENT,
    Assessment,
    Evidence,
    Policy,
    Verdict,
    assess,
)

_SECRET_ENV = "AWNEST_SECRET"


# ── self-test ──────────────────────────────────────────────────────────────
# Everything asserted here is PURE: no key material on disk, no service, no
# clock beyond an injected `now`. A self-test that needs a live dependency is a
# self-test that gets skipped, and a skipped check is indistinguishable from a
# passing one.


class _OtherAlgKey:
    """A key that claims a different algorithm. Exists so the alg-confusion refusal
    can be proven WITHOUT installing the optional asymmetric backend -- otherwise
    that assertion would silently not run on most machines."""

    alg = "ed25519"

    def sign(self, msg: bytes) -> bytes:  # pragma: no cover - never reached
        raise AssertionError("the self-test must not reach signing on this key")

    def check(self, msg: bytes, sig: bytes) -> bool:  # pragma: no cover
        raise AssertionError(
            "alg must be rejected BEFORE the signature is checked -- reaching here "
            "means the token got to choose the algorithm"
        )


def _raises(fn, *args, **kwargs) -> bool:
    """True when `fn` refuses. A named helper rather than a bare try/except at each
    site: the swallowing shape is how a check that no longer checks anything still
    reads as a check."""
    try:
        fn(*args, **kwargs)
    except (ValueError, AttestationError, NotAdmitted):
        return True
    return False


def _self_test() -> int:  # noqa: C901 - a flat list of independent assertions
    f: list[str] = []
    t = 1_700_000_000.0
    secret = "self-test-secret-not-a-real-key"
    key = HmacKey(secret)

    # 1. THE RULE THE PACKAGE EXISTS FOR: no evidence is not a pass, and an
    #    unjudged signal is not a zero and not a pass either.
    if assess([], now=t).verdict is not Verdict.UNKNOWN:
        f.append("empty evidence did not come back UNKNOWN")
    unjudged = Evidence("judged_challenges", None, at=t, source="a judge that was down")
    a = assess([unjudged], now=t)
    if a.verdict is not Verdict.UNKNOWN:
        f.append("an UNJUDGED signal admitted somebody -- the fail-open this package is for")
    if not any("not judged" in r for r in a.reasons):
        f.append("an unjudged signal was discarded without saying so")
    if a.score == 0:
        f.append("unjudged was reported as a score of zero; those are different facts")

    # 2. An honest declaration is believed and is not a failure.
    a = assess([Evidence(DECLARED_AGENT, None, at=t, source="ci-bot")], now=t)
    if a.verdict is not Verdict.AGENT:
        f.append("a declared agent was not recorded as an agent")
    if a.admitted(Policy()) or not a.admitted(Policy(allow_agents=True)):
        f.append("allow_agents did not decide the agent door")
    # ...even when a human-looking signal is presented alongside. Otherwise the
    # cheapest strategy for automation is to declare AND submit, which is the
    # opposite of what a declaration should buy.
    mixed = assess([Evidence("judged_challenges", 99, at=t),
                    Evidence(DECLARED_AGENT, None, at=t)], now=t)
    if mixed.verdict is not Verdict.AGENT:
        f.append("a declaration was outvoted by a score -- declaring must not be losable")

    # 3. Scores must EARN it: freshness, threshold, count, and no clock tricks.
    pol = Policy(min_score=65, max_age_s=3600, min_signals=1)
    if assess([Evidence("k", 64, at=t)], pol, now=t).verdict is not Verdict.UNKNOWN:
        f.append("a score one point under the threshold was admitted")
    if assess([Evidence("k", 65, at=t)], pol, now=t).verdict is not Verdict.HUMAN:
        f.append("a score exactly at the threshold was refused; the bound is inclusive")
    if assess([Evidence("k", 99, at=t - 3601)], pol, now=t).verdict is not Verdict.UNKNOWN:
        f.append("a stale signal was admitted -- a human check is a fact about a moment")
    if assess([Evidence("k", 99, at=t + 600)], pol, now=t).verdict is not Verdict.UNKNOWN:
        f.append("a signal from the future was admitted -- forging a timestamp cannot work")
    two = Policy(min_score=65, max_age_s=3600, min_signals=2)
    if assess([Evidence("k", 99, at=t)], two, now=t).verdict is not Verdict.UNKNOWN:
        f.append("min_signals=2 was satisfied by one signal")
    a = assess([Evidence("k", 99, at=t), Evidence("j", 70, at=t)], two, now=t)
    if a.verdict is not Verdict.HUMAN or a.score != 70:
        f.append(f"stacked signals must report the LOWEST (got {a.score}), never a mean")

    # 4. The attestation carries EXACTLY the fields that make it non-transferable.
    #    A missing `aud` is a skeleton key; a missing `sub` is a transferable one.
    body = payload_for(sub="u1", aud="door", verdict=Verdict.HUMAN, score=80,
                       iat=t, ttl_s=60, nonce="n", method="m", alg="hs256")
    if tuple(body) != ATTESTATION_FIELDS:
        f.append(f"payload keys {tuple(body)} != declared {ATTESTATION_FIELDS}")
    for kwargs, why in (
        ({"sub": ""}, "no subject"),
        ({"aud": ""}, "no audience"),
        ({"verdict": Verdict.UNKNOWN}, "an UNKNOWN verdict"),
        ({"ttl_s": 0}, "no lifetime"),
    ):
        args = {"sub": "u1", "aud": "door", "verdict": Verdict.HUMAN, "score": 80,
                "iat": t, "ttl_s": 60, "nonce": "n", "method": "m", "alg": "hs256"}
        args.update(kwargs)
        if not _raises(payload_for, **args):
            f.append(f"minted an attestation with {why}")

    # 5. Round trip, and every way it must NOT round trip.
    token = mint(key, sub="u1", aud="door", verdict=Verdict.HUMAN, score=80,
                 ttl_s=3600, method="challenges", now=t)
    att = verify(token, key, audience="door", subject="u1", now=t + 10)
    if att.verdict is not Verdict.HUMAN or att.score != 80:
        f.append("a valid attestation did not survive its own round trip")
    if not _raises(verify, token, key, audience="other-door", now=t + 10):
        f.append("an attestation for one door opened another -- the replay this format exists for")
    if not _raises(verify, token, key, audience="door", subject="u2", now=t + 10):
        f.append("an attestation about one subject verified for another")
    if not _raises(verify, token, key, audience="door", now=t + 7200):
        f.append("an expired attestation verified")
    if not _raises(verify, token, key, audience="door", now=t - 3600):
        f.append("an attestation verified an hour before it was issued")
    if not _raises(verify, token, HmacKey("a-different-secret-entirely!!"),
                   audience="door", now=t + 10):
        f.append("an attestation verified under the wrong key")
    if not _raises(verify, token, _OtherAlgKey(), audience="door", now=t + 10):
        f.append("alg confusion: the token was allowed to choose the algorithm")
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload}.{sig[:-2]}{'AB' if sig[-2:] != 'AB' else 'AC'}"
    if not _raises(verify, tampered, key, audience="door", now=t + 10):
        f.append("a tampered signature verified")
    if not _raises(verify, f"{head}.{payload}", key, audience="door", now=t + 10):
        f.append("a token with no signature segment verified")

    # 6. One use, if you keep a ledger.
    seen = MemorySeen()
    verify(token, key, audience="door", now=t + 10, seen=seen)
    if not _raises(verify, token, key, audience="door", now=t + 10, seen=seen):
        f.append("an attestation was spendable twice against one seen-set")

    # 7. The door re-judges what the issuer decided.
    strict = Nest("door", key=key, policy=Policy(min_score=65, max_age_s=60))
    if strict.admit(token=token, subject="u1", now=t + 3000).verdict is not Verdict.UNKNOWN:
        f.append("a long-lived token overrode the DOOR's freshness policy")
    weak = mint(key, sub="u1", aud="door", verdict=Verdict.HUMAN, score=50, ttl_s=3600,
                method="challenges", now=t)
    if Nest("door", key=key).admit(token=weak, subject="u1", now=t).verdict is not Verdict.UNKNOWN:
        f.append("a signed score below the door's threshold was admitted anyway")
    keyless = Nest("door")
    if keyless.admit(token=token, subject="u1", now=t + 10).verdict is not Verdict.UNKNOWN:
        f.append("a nest with no key accepted a token it could not check")
    if not _raises(keyless.issue, "u1", Assessment(Verdict.HUMAN, 90)):
        f.append("a nest with no key issued an attestation")
    if not _raises(Nest("door", key=key).require, token=tampered, subject="u1", now=t + 10):
        f.append("require() did not raise on a refused token")
    # A presented-but-invalid credential must not fall through to other evidence.
    fell_through = Nest("door", key=key).admit(
        token=tampered, evidence=[Evidence("judged_challenges", 99, at=t)], now=t + 10)
    if fell_through.verdict is not Verdict.UNKNOWN:
        f.append("a forged token fell through to the evidence path instead of refusing")
    if Nest("door", key=key).door(token=token, subject="u1", now=t + 10) != "human":
        f.append("door() did not name the human door for a valid human attestation")

    # 8. Challenges: a set is never one question twice, and short answers carry
    #    nothing.
    r = random.Random(7)
    for _ in range(50):
        picked = select(3, rng=r)
        if len({c.category for c in picked}) != 3:
            f.append("select() returned two challenges from one category")
            break
    if not _raises(select, len(CATEGORIES) + 1):
        f.append("select() agreed to repeat a category rather than refusing")
    if "criteria" in CHALLENGES[0].public():
        f.append("public() shipped the answer key to the person being tested")
    one = (CHALLENGES[0],)
    good = {CHALLENGES[0].id: "x" * 40}
    check_answers(one, good)
    for bad, why in (({CHALLENGES[0].id: "too short"}, "an answer under the floor"),
                     ({CHALLENGES[0].id: "x" * 5000}, "an answer over the ceiling"),
                     ({}, "no answer at all"),
                     ({CHALLENGES[0].id: "x" * 40, "not_issued": "x" * 40},
                      "an answer to a challenge nobody issued")):
        if not _raises(check_answers, one, bad):
            f.append(f"check_answers accepted {why}")
    if CHALLENGES[0].criteria not in judge_prompt(one, good):
        f.append("the judge prompt omitted the criteria, so the judge scores blind")

    # 9. Reading the judge STRICTLY -- the scale trap above all.
    ok = parse_judgement('{"scores": {"a": 80}, "overall": 80, "verdict": "human", '
                         '"reasoning": "x"}')
    if ok.overall != 80 or ok.verdict != "human":
        f.append("a well-formed judgement did not parse")
    if not parse_judgement('```json\n{"scores": {"a": 1}, "overall": 1, '
                           '"verdict": "likely_bot", "reasoning": "x"}\n```').overall == 1:
        f.append("a fenced judgement was refused, or 1 was silently rescaled to 100")
    for bad, why in (
        ('{"scores": {"a": 80}, "verdict": "human", "reasoning": "x"}', "no overall"),
        ('{"overall": 80, "verdict": "human", "reasoning": "x"}', "no per-challenge scores"),
        ('{"scores": {"a": 80}, "overall": 0.9, "verdict": "human", "reasoning": "x"}',
         "a 0-1 score that would invert if rescaled"),
        ('{"scores": {"a": 80}, "overall": 80, "verdict": "probably", "reasoning": "x"}',
         "an unknown verdict"),
        ("the answers seem human to me", "prose instead of JSON"),
        ("", "nothing at all"),
    ):
        if not _raises(parse_judgement, bad):
            f.append(f"parse_judgement accepted {why}")
    if not _raises(parse_judgement,
                   '{"scores": {"a": 80}, "overall": 80, "verdict": "human", "reasoning": "x"}',
                   expect=["a", "b"]):
        f.append("a judge that scored only some challenges was accepted")
    if tuple(JUDGEMENT_FIELDS) != ("scores", "overall", "verdict", "reasoning"):
        f.append("the required judgement fields drifted from what the prompt asks for")

    # 10. The client's wire shape, including the field that is NOT in the body.
    b = submit_body(["a"], {"a": "x" * 40})
    if tuple(b) != SUBMIT_FIELDS:
        f.append(f"submit body keys {tuple(b)} != declared {SUBMIT_FIELDS}")
    if SESSION_HEADER != "X-Verification-Session":
        f.append("the session header was renamed; the service will 422 about a missing header")
    if "session_id" in b:
        f.append("the session id was put in the BODY -- it travels in a header")
    if not _raises(submit_body, ["a"], {}):
        f.append("submit_body sent a challenge with no answer")

    # 11. The context binding, in BOTH directions. The one that would otherwise
    #     pass silently is a BOUND token at an UNBOUND verifier -- that is how a
    #     commit attestation gets spent on a login.
    bound = mint(key, sub="u1", aud="door", verdict=Verdict.HUMAN, score=80, ttl_s=3600,
                 method="m", ctx="tree:abc123", now=t)
    if not _raises(verify, bound, key, audience="door", now=t + 10):
        f.append("a CONTEXT-BOUND token verified at a verifier that named no context")
    if not _raises(verify, bound, key, audience="door", context="tree:def456", now=t + 10):
        f.append("a token bound to one thing verified against another")
    if not _raises(verify, token, key, audience="door", context="tree:abc123", now=t + 10):
        f.append("an UNBOUND token satisfied a verifier that required a binding")
    if verify(bound, key, audience="door", context="tree:abc123", now=t + 10).ctx != "tree:abc123":
        f.append("a correctly bound token did not survive its round trip")

    # 12. Audiences are BUILT, never typed. An issuer typo mints tokens for a door
    #     nobody guards, and nothing anywhere reports it.
    if audience("channel", "#playground") != "channel:#playground":
        f.append("audience() changed shape; every issuer and verifier disagrees now")
    if parse_audience("repo:acme/widgets") != ("repo", "acme/widgets"):
        f.append("parse() did not round-trip an audience")
    for kind, name, why in (("chan", "x", "an unknown kind"), ("channel", "", "no name"),
                            ("channel", "*", "a wildcard"), ("repo", "a b", "whitespace")):
        if not _raises(audience, kind, name):
            f.append(f"audience() built a door from {why}")
    if "repo" not in KINDS or "mesh" not in KINDS or "tunnel" not in KINDS:
        f.append("a kind the family already gates on went missing from KINDS")

    # 13. Commit attestations bind to CONTENT, and a verifier that skips that check
    #     accepts an attestation lifted off another commit.
    tree_a = "a" * 40
    tree_b = "b" * 40
    tok = attest_commit(key, identity="u1", tree_sha=tree_a, repo="acme/widgets",
                        score=80, ttl_s=3600, method="challenges", now=t)
    msg = f"""feat: a thing

{trailer_line(tok)}
"""
    if find_trailer(msg) != tok:
        f.append("the trailer did not survive being written into a commit message")
    got = verify_commit(msg, key, repo="acme/widgets", tree_sha=tree_a, identity="u1",
                        now=t + 10)
    if got.verdict is not Verdict.HUMAN or got.score != 80:
        f.append("a valid commit attestation did not verify")
    if not _raises(verify_commit, msg, key, repo="acme/widgets", tree_sha=tree_b, now=t + 10):
        f.append("an attestation verified against DIFFERENT content -- it can be lifted")
    if not _raises(verify_commit, msg, key, repo="other/repo", tree_sha=tree_a, now=t + 10):
        f.append("a commit attestation for one repo verified in another")
    if not _raises(verify_commit, "feat: no trailer here", key, repo="acme/widgets",
                   tree_sha=tree_a, now=t + 10):
        f.append("an UNATTESTED commit verified -- absence must raise, never return None")
    if not _raises(tree_context, "HEAD"):
        f.append("tree_context accepted something that is not an object id")
    if repo_audience("acme/widgets", "release") == repo_audience("acme/widgets"):
        f.append("a branch-specific door collapsed into the repo-wide one")

    if f:
        print("SELF-TEST FAILURES:")
        for line in f:
            print("  x " + line)
        return 1
    print("awnest self-test: ok")
    return 0


# ── commands ───────────────────────────────────────────────────────────────


def _secret(args: argparse.Namespace) -> str:
    s = args.secret or os.environ.get(_SECRET_ENV, "")
    if not s:
        raise SystemExit(
            f"no signing secret: pass --secret or set {_SECRET_ENV}. This is not "
            "defaulted on purpose -- a default key is a key everybody has."
        )
    return s


def _cmd_challenge(args: argparse.Namespace) -> int:
    picked = select(args.number)
    print(json.dumps({
        "issued_at": time.time(),
        "challenges": [c.public() for c in picked],
    }, indent=2))
    return 0


def _cmd_judge(args: argparse.Namespace) -> int:
    from awnest.judge import JudgeError, score_answers  # httpx only when needed

    try:
        answers = json.loads(open(args.answers, encoding="utf-8").read())
    except (OSError, ValueError) as exc:
        print(f"cannot read --answers: {exc}", file=sys.stderr)
        return 2
    if not isinstance(answers, dict):
        print("--answers must be a JSON object of challenge_id -> answer", file=sys.stderr)
        return 2
    picked = [c for c in CHALLENGES if c.id in answers]
    if len(picked) != len(answers):
        unknown = sorted(set(answers) - {c.id for c in picked})
        print(f"unknown challenge id(s): {unknown}", file=sys.stderr)
        return 2
    try:
        evidence, judgement = score_answers(args.url, picked, answers, model=args.model,
                                            token=args.token)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except JudgeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({
        "score": evidence.score, "verdict": judgement.verdict,
        "per_challenge": judgement.scores, "reasoning": judgement.reasoning,
    }, indent=2))
    return 0


def _cmd_mint(args: argparse.Namespace) -> int:
    try:
        v = Verdict(args.verdict)
        token = mint(HmacKey(_secret(args)), sub=args.subject, aud=args.audience,
                     verdict=v, score=args.score, ttl_s=args.ttl, method=args.method)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(token)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        att = verify(args.token, HmacKey(_secret(args)), audience=args.audience,
                     subject=args.subject)
    except AttestationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "subject": att.sub, "audience": att.aud, "verdict": att.verdict.value,
        "score": att.score, "method": att.method, "age_s": int(att.age_s()),
    }, indent=2))
    return 0


def _cmd_gate(args: argparse.Namespace) -> int:
    nest = Nest(args.audience, key=HmacKey(_secret(args)),
                policy=Policy(min_score=args.min_score, max_age_s=args.max_age,
                              allow_agents=args.allow_agents))
    a = nest.admit(token=args.token, subject=args.subject)
    verdict_line = f"{a.verdict.value} (score={a.score})"
    if a.admitted(nest.policy):
        print(f"ADMITTED to {args.audience}: {verdict_line}")
        return 0
    print(f"REFUSED at {args.audience}: {verdict_line}", file=sys.stderr)
    for r in a.reasons:
        print(f"  - {r}", file=sys.stderr)
    return 1


def _cmd_commit_attest(args: argparse.Namespace) -> int:
    try:
        token = attest_commit(HmacKey(_secret(args)), identity=args.identity,
                              tree_sha=args.tree, repo=args.repo, ref=args.ref,
                              verdict=Verdict(args.verdict), score=args.score,
                              method=args.method)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(trailer_line(token))
    return 0


def _cmd_commit_verify(args: argparse.Namespace) -> int:
    try:
        message = open(args.message, encoding="utf-8").read()
    except OSError as exc:
        print(f"cannot read the commit message: {exc}", file=sys.stderr)
        return 2
    try:
        att = verify_commit(message, HmacKey(_secret(args)), repo=args.repo,
                            tree_sha=args.tree, ref=args.ref, identity=args.identity)
    except AttestationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"identity": att.sub, "audience": att.aud, "content": att.ctx,
                      "verdict": att.verdict.value, "score": att.score,
                      "method": att.method}, indent=2))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="awnest", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true", help="prove this package can still fail")
    p.add_argument("--secret", default=None, help=f"signing secret (or {_SECRET_ENV})")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("challenge", help="issue a set of challenges")
    c.add_argument("-n", "--number", type=int, default=3)
    c.set_defaults(fn=_cmd_challenge)

    j = sub.add_parser("judge", help="score answers with an OpenAI-compatible endpoint")
    j.add_argument("--url", required=True)
    j.add_argument("--model", required=True)
    j.add_argument("--answers", required=True, help="JSON file: challenge_id -> answer")
    j.add_argument("--token", default=os.environ.get("AWNEST_JUDGE_TOKEN") or None)
    j.set_defaults(fn=_cmd_judge)

    m = sub.add_parser("mint", help="sign an attestation")
    m.add_argument("--subject", required=True)
    m.add_argument("--audience", required=True)
    m.add_argument("--verdict", default="human", choices=[v.value for v in Verdict])
    m.add_argument("--score", type=int, default=None)
    m.add_argument("--ttl", type=float, default=3600.0)
    m.add_argument("--method", default="unspecified")
    m.set_defaults(fn=_cmd_mint)

    v = sub.add_parser("verify", help="check an attestation against one door")
    v.add_argument("token")
    v.add_argument("--audience", required=True)
    v.add_argument("--subject", default=None)
    v.set_defaults(fn=_cmd_verify)

    g = sub.add_parser("gate", help="admit or refuse, with reasons and an exit code")
    g.add_argument("token")
    g.add_argument("--audience", required=True)
    g.add_argument("--subject", default=None)
    g.add_argument("--min-score", type=int, default=Policy().min_score)
    g.add_argument("--max-age", type=float, default=Policy().max_age_s)
    g.add_argument("--allow-agents", action="store_true")
    g.set_defaults(fn=_cmd_gate)

    ca = sub.add_parser("commit-attest", help=f"print a {TRAILER} trailer for a commit")
    ca.add_argument("--identity", required=True, help="the identity system's id, not a name")
    ca.add_argument("--tree", required=True, help="git rev-parse HEAD^{tree}")
    ca.add_argument("--repo", required=True)
    ca.add_argument("--ref", default=None, help="for a branch-specific door")
    ca.add_argument("--verdict", default="human", choices=[v.value for v in Verdict])
    ca.add_argument("--score", type=int, default=None)
    ca.add_argument("--method", default="unspecified")
    ca.set_defaults(fn=_cmd_commit_attest)

    cv = sub.add_parser("commit-verify", help="verify a commit's trailer against its content")
    cv.add_argument("--message", required=True, help="file holding the commit message")
    cv.add_argument("--tree", required=True)
    cv.add_argument("--repo", required=True)
    cv.add_argument("--ref", default=None)
    cv.add_argument("--identity", default=None)
    cv.set_defaults(fn=_cmd_commit_verify)

    args = p.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not getattr(args, "fn", None):
        p.print_help()
        return 2
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
