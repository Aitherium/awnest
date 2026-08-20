"""Tests for awnest.

Every test here asserts something a caller could get WRONG in a way nothing else
reports. The CLI's `--self-test` covers the same invariants without pytest, so the
package can prove itself on a machine with nothing installed; this file adds the
cases that need a fake transport or a real filesystem.
"""
from __future__ import annotations

import time

import httpx
import pytest
from awnest import (
    CHALLENGES,
    DECLARED_AGENT,
    Assessment,
    AttestationError,
    Evidence,
    FileSeen,
    HmacKey,
    MemorySeen,
    Nest,
    NotAdmitted,
    Policy,
    Verdict,
    assess,
    check_answers,
    mint,
    parse_judgement,
    select,
    verify,
)
from awnest.audience import audience
from awnest.audience import parse as parse_audience
from awnest.client import HumanityClient, NestClientError
from awnest.commit import (
    attest_commit,
    find_trailer,
    repo_audience,
    trailer_line,
    verify_commit,
)
from awnest.judge import JudgeError, score_answers

T = 1_700_000_000.0
SECRET = "a-test-secret-that-is-long-enough"


# ── the verdict plane ──────────────────────────────────────────────────────


def test_no_evidence_is_not_a_pass():
    a = assess([], now=T)
    assert a.verdict is Verdict.UNKNOWN
    assert not a.admitted(Policy())


def test_unjudged_is_not_a_zero_and_not_a_pass():
    a = assess([Evidence("judged_challenges", None, at=T)], now=T)
    assert a.verdict is Verdict.UNKNOWN
    assert a.score is None            # not 0 -- "nobody scored it" is its own fact
    assert any("not judged" in r for r in a.reasons)


def test_a_declared_agent_gets_the_agent_door_not_a_refusal():
    a = assess([Evidence(DECLARED_AGENT, None, at=T, source="ci")], now=T)
    assert a.verdict is Verdict.AGENT
    assert not a.admitted(Policy())
    assert a.admitted(Policy(allow_agents=True))


def test_declaring_cannot_be_outvoted_by_a_good_score():
    # Otherwise the cheapest strategy for automation is to declare AND submit,
    # and honesty has to be the cheaper path or nobody takes it.
    a = assess([Evidence("judged_challenges", 99, at=T),
                Evidence(DECLARED_AGENT, None, at=T)], now=T)
    assert a.verdict is Verdict.AGENT


@pytest.mark.parametrize("age,expected", [(0, Verdict.HUMAN), (3599, Verdict.HUMAN),
                                          (3601, Verdict.UNKNOWN)])
def test_freshness_is_enforced(age, expected):
    pol = Policy(min_score=65, max_age_s=3600)
    assert assess([Evidence("k", 90, at=T - age)], pol, now=T).verdict is expected


def test_a_future_timestamp_is_refused_not_treated_as_fresh():
    pol = Policy(min_score=65, max_age_s=3600)
    assert assess([Evidence("k", 90, at=T + 60)], pol, now=T).verdict is Verdict.UNKNOWN


def test_stacked_signals_report_the_weakest():
    pol = Policy(min_score=65, min_signals=2, max_age_s=3600)
    a = assess([Evidence("a", 99, at=T), Evidence("b", 70, at=T)], pol, now=T)
    assert a.verdict is Verdict.HUMAN and a.score == 70


def test_a_score_outside_the_range_is_a_construction_error():
    with pytest.raises(ValueError):
        Evidence("k", 101)
    with pytest.raises(ValueError):
        Evidence("k", -1)
    with pytest.raises(ValueError):
        Evidence("k", True)          # bool is an int in python; it is not a score


# ── attestations ───────────────────────────────────────────────────────────


def _token(**over):
    args = dict(sub="u1", aud="door", verdict=Verdict.HUMAN, score=80,
                ttl_s=3600, method="challenges", now=T)
    args.update(over)
    return mint(HmacKey(SECRET), **args)


def test_round_trip():
    att = verify(_token(), HmacKey(SECRET), audience="door", subject="u1", now=T + 5)
    assert att.verdict is Verdict.HUMAN and att.score == 80 and att.sub == "u1"


@pytest.mark.parametrize("kwargs", [
    {"audience": "another-door"},
    {"audience": "door", "subject": "someone-else"},
])
def test_binding_is_enforced(kwargs):
    with pytest.raises(AttestationError):
        verify(_token(), HmacKey(SECRET), now=T + 5, **kwargs)


def test_expiry_and_the_wrong_key():
    with pytest.raises(AttestationError):
        verify(_token(), HmacKey(SECRET), audience="door", now=T + 7200)
    with pytest.raises(AttestationError):
        verify(_token(), HmacKey("an-entirely-different-secret"), audience="door", now=T + 5)


def test_an_unknown_verdict_cannot_be_minted():
    with pytest.raises(ValueError):
        _token(verdict=Verdict.UNKNOWN)


def test_a_short_secret_is_refused():
    with pytest.raises(ValueError):
        HmacKey("short")


def test_one_use_against_a_seen_set():
    seen = MemorySeen()
    tok = _token()
    verify(tok, HmacKey(SECRET), audience="door", now=T + 5, seen=seen)
    with pytest.raises(AttestationError):
        verify(tok, HmacKey(SECRET), audience="door", now=T + 5, seen=seen)


def test_file_seen_is_atomic_and_shared(tmp_path):
    a = FileSeen(tmp_path)
    b = FileSeen(tmp_path)          # a second process would look like this
    assert a.mark("n1", T + 60, T) is True
    assert b.mark("n1", T + 60, T) is False


def test_file_seen_sweeps_only_what_expired(tmp_path):
    s = FileSeen(tmp_path)
    s.mark("old", T - 1, T - 10)
    s.mark("live", T + 600, T)
    assert s.sweep(T) == 1
    assert s.mark("old", T + 600, T) is True     # replayable again, correctly: it expired
    assert s.mark("live", T + 600, T) is False   # still spent


def test_a_corrupt_ledger_entry_is_kept_not_freed(tmp_path):
    s = FileSeen(tmp_path)
    s.mark("n1", T + 600, T)
    for f in tmp_path.iterdir():
        f.write_text("not a number", encoding="utf-8")
    assert s.sweep(T) == 0
    assert s.mark("n1", T + 600, T) is False


# ── the door ───────────────────────────────────────────────────────────────


def test_the_door_may_be_stricter_than_the_issuer():
    nest = Nest("door", key=HmacKey(SECRET), policy=Policy(max_age_s=60))
    assert nest.admit(token=_token(), subject="u1", now=T + 3000).verdict is Verdict.UNKNOWN


def test_a_forged_token_does_not_fall_through_to_other_evidence():
    head, payload, sig = _token().split(".")
    forged = f"{head}.{payload}.{sig[:-2]}{'AB' if sig[-2:] != 'AB' else 'AC'}"
    nest = Nest("door", key=HmacKey(SECRET))
    a = nest.admit(token=forged, evidence=[Evidence("judged_challenges", 99, at=T)], now=T)
    assert a.verdict is Verdict.UNKNOWN
    assert any("refused" in r for r in a.reasons)


def test_require_raises_with_the_reason():
    nest = Nest("door", key=HmacKey(SECRET))
    with pytest.raises(NotAdmitted) as e:
        nest.require(token=_token(aud="elsewhere"), subject="u1", now=T + 5)
    assert "not admitted to 'door'" in str(e.value)


def test_a_nest_with_no_key_refuses_rather_than_trusting():
    nest = Nest("door")
    assert nest.admit(token=_token(), now=T + 5).verdict is Verdict.UNKNOWN
    with pytest.raises(AttestationError):
        nest.issue("u1", Assessment(Verdict.HUMAN, 90))


def test_issue_then_admit_is_a_closed_loop():
    nest = Nest("door", key=HmacKey(SECRET))
    tok = nest.issue("u1", Assessment(Verdict.HUMAN, 90), ttl_s=600,
                     method="challenges", now=T)
    assert nest.require(token=tok, subject="u1", now=T + 5).verdict is Verdict.HUMAN


def test_an_audience_is_mandatory():
    with pytest.raises(ValueError):
        Nest("")


# ── challenges and judgements ──────────────────────────────────────────────


def test_a_set_never_asks_one_category_twice():
    for _ in range(100):
        picked = select(3)
        assert len({c.category for c in picked}) == 3


def test_the_criteria_never_reach_the_person_being_tested():
    assert "criteria" not in CHALLENGES[0].public()


def test_answer_bounds():
    c = CHALLENGES[0]
    check_answers([c], {c.id: "x" * 40})
    with pytest.raises(ValueError):
        check_answers([c], {c.id: "short"})
    with pytest.raises(ValueError):
        check_answers([c], {c.id: "x" * 5000})


@pytest.mark.parametrize("bad", [
    '{"scores": {"a": 80}, "verdict": "human", "reasoning": "x"}',
    '{"scores": {}, "overall": 80, "verdict": "human", "reasoning": "x"}',
    '{"scores": {"a": 0.9}, "overall": 0.9, "verdict": "human", "reasoning": "x"}',
    '{"scores": {"a": 80}, "overall": 800, "verdict": "human", "reasoning": "x"}',
    "looks human to me",
    "",
])
def test_a_judgement_is_read_strictly(bad):
    with pytest.raises(ValueError):
        parse_judgement(bad)


def test_a_fenced_integer_judgement_parses_without_rescaling():
    j = parse_judgement('```json\n{"scores": {"a": 1}, "overall": 1, '
                        '"verdict": "likely_bot", "reasoning": "x"}\n```')
    assert j.overall == 1           # not 100


def test_partial_scoring_is_refused():
    with pytest.raises(ValueError):
        parse_judgement('{"scores": {"a": 80}, "overall": 80, "verdict": "human", '
                        '"reasoning": "x"}', expect=["a", "b"])


# ── the wire ───────────────────────────────────────────────────────────────


def _client(handler) -> HumanityClient:
    transport = httpx.MockTransport(handler)
    return HumanityClient("https://example.invalid",
                          client=httpx.Client(transport=transport))


def test_the_session_travels_in_a_header_not_the_body():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/challenge"):
            return httpx.Response(200, json={
                "session_id": "sess-1", "expires_at": "later",
                "challenges": [{"id": "exp_memory", "category": "experiential",
                                "prompt": "..."}]})
        seen["header"] = request.headers.get("X-Verification-Session")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"humanity_verified": True, "humanity_score": 82,
                                         "humanity_verdict": "human"})

    c = _client(handler)
    issued = c.challenge()
    ev = c.submit(issued, {"exp_memory": "x" * 40})
    assert seen["header"] == "sess-1"
    assert "session_id" not in seen["body"]
    assert ev.score == 82 and ev.kind == "judged_challenges"


def test_a_503_raises_rather_than_reading_as_a_failed_check():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/challenge"):
            return httpx.Response(200, json={
                "session_id": "s", "challenges": [{"id": "exp_memory", "prompt": "..."}]})
        return httpx.Response(503, json={"detail": "judge unavailable"})

    c = _client(handler)
    issued = c.challenge()
    with pytest.raises(NestClientError):
        c.submit(issued, {"exp_memory": "x" * 40})


def test_a_response_with_no_score_is_refused_not_inferred():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/challenge"):
            return httpx.Response(200, json={
                "session_id": "s", "challenges": [{"id": "exp_memory", "prompt": "..."}]})
        return httpx.Response(200, json={"humanity_verified": True})

    c = _client(handler)
    issued = c.challenge()
    with pytest.raises(NestClientError):
        c.submit(issued, {"exp_memory": "x" * 40})


def test_no_token_means_no_authorization_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = "authorization" in request.headers
        return httpx.Response(200, json={"session_id": "s",
                                         "challenges": [{"id": "exp_memory", "prompt": "p"}]})

    _client(handler).challenge()
    assert seen["auth"] is False     # never an empty `Bearer `, which 401s differently


def test_the_judge_raises_instead_of_returning_a_zero():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "I think they are probably human!"}}]})

    c = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(JudgeError):
        score_answers("https://example.invalid", [CHALLENGES[0]],
                      {CHALLENGES[0].id: "x" * 40}, model="m", client=c)


def test_the_judge_returns_evidence_that_is_dated_now():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content":
            '{"scores": {"exp_memory": 77}, "overall": 77, "verdict": "human", '
            '"reasoning": "specific and uneven"}'}}]})

    c = httpx.Client(transport=httpx.MockTransport(handler))
    ev, j = score_answers("https://example.invalid", [CHALLENGES[0]],
                          {CHALLENGES[0].id: "x" * 40}, model="m", client=c)
    assert ev.score == 77 and j.verdict == "human"
    assert abs(ev.at - time.time()) < 60


# ── bindings, doors and commits ────────────────────────────────────────────


def test_a_bound_token_is_refused_where_nobody_checks_the_binding():
    tok = mint(HmacKey(SECRET), sub="u1", aud="door", verdict=Verdict.HUMAN,
               score=80, ttl_s=3600, ctx="tree:abc", now=T)
    with pytest.raises(AttestationError):
        verify(tok, HmacKey(SECRET), audience="door", now=T + 5)


def test_an_unbound_token_cannot_satisfy_a_verifier_that_needs_a_binding():
    with pytest.raises(AttestationError):
        verify(_token(), HmacKey(SECRET), audience="door", context="tree:abc", now=T + 5)


def test_audiences_are_built_not_typed():
    assert audience("channel", "#playground") == "channel:#playground"
    assert parse_audience("mesh:home") == ("mesh", "home")
    for kind, name in (("chan", "x"), ("channel", ""), ("channel", "*"), ("repo", "a b")):
        with pytest.raises(ValueError):
            audience(kind, name)


def test_a_commit_attestation_cannot_be_lifted_onto_other_content():
    key = HmacKey(SECRET)
    tok = attest_commit(key, identity="u1", tree_sha="a" * 40, repo="acme/widgets",
                        score=80, now=T)
    msg = "feat: thing" + "\n\n" + trailer_line(tok) + "\n"
    assert verify_commit(msg, key, repo="acme/widgets", tree_sha="a" * 40,
                         identity="u1", now=T + 5).score == 80
    with pytest.raises(AttestationError):
        verify_commit(msg, key, repo="acme/widgets", tree_sha="b" * 40, now=T + 5)
    with pytest.raises(AttestationError):
        verify_commit(msg, key, repo="other/repo", tree_sha="a" * 40, now=T + 5)


def test_an_unattested_commit_raises_rather_than_returning_none():
    with pytest.raises(AttestationError):
        verify_commit("feat: no trailer", HmacKey(SECRET), repo="acme/widgets",
                      tree_sha="a" * 40, now=T)


def test_the_last_trailer_wins():
    key = HmacKey(SECRET)
    old = attest_commit(key, identity="u1", tree_sha="a" * 40, repo="acme/widgets", now=T)
    new = attest_commit(key, identity="u2", tree_sha="a" * 40, repo="acme/widgets", now=T)
    msg = "feat: rebased" + "\n\n" + trailer_line(old) + "\n" + trailer_line(new) + "\n"
    assert find_trailer(msg) == new


def test_a_branch_door_is_not_the_repo_door():
    assert repo_audience("acme/widgets", "release") != repo_audience("acme/widgets")


def test_a_nest_can_bind_an_action_to_its_content():
    nest = Nest("action:transfer", key=HmacKey(SECRET))
    tok = nest.issue("u1", Assessment(Verdict.HUMAN, 90), ttl_s=600,
                     context="body:deadbeef", now=T)
    assert nest.require(token=tok, subject="u1", context="body:deadbeef",
                        now=T + 5).verdict is Verdict.HUMAN
    # ...and the same token cannot approve a different transfer, or an unbound door
    assert nest.admit(token=tok, subject="u1", context="body:0000",
                      now=T + 5).verdict is Verdict.UNKNOWN
    assert nest.admit(token=tok, subject="u1", now=T + 5).verdict is Verdict.UNKNOWN
