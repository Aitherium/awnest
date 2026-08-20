"""The nest itself: one door, one policy, one answer.

A nest is not a wall. It is a place with doors, and the job is knowing who came
through which one. `Nest` holds the audience it protects, the policy that door
requires, and the key it trusts -- and answers exactly one question: does this
caller come in.

WHAT IT REFUSES TO DO
====================
It never returns a bare bool. `admit()` returns an Assessment carrying the reason,
and `require()` raises. Both shapes exist because the two call sites want opposite
ergonomics and the same rigour, and because `if nest.check(user):` is the line that
gets inverted, wrapped in a `try` that swallows, or quietly left off a new route --
after which nothing anywhere reports that the door stopped being a door.

A PRESENTED-BUT-INVALID CREDENTIAL IS NOT AN ABSENT ONE
=======================================================
If a caller hands over a token that does not verify -- wrong audience, expired,
tampered, already spent -- the nest refuses THERE, and does not fall through to
whatever other evidence was supplied. Falling through is not exploitable on its
own (the other evidence still has to qualify), but it turns a forged credential
into an ordinary quiet retry, and forgery is the one event you want to be loud.
"""
from __future__ import annotations

import time
from typing import Iterable, Optional, Sequence

from awnest.attest import Attestation, AttestationError, Key, Seen, mint, verify
from awnest.verdict import Assessment, Evidence, Policy, Verdict, assess

__all__ = ["Nest", "NotAdmitted"]


class NotAdmitted(PermissionError):  # noqa: N818 - reads at the call site: `except NotAdmitted`. An Error suffix would say less, not more.
    """The door stays shut, and this says why.

    Carries the Assessment so a caller can log the reason, show the human which
    signal went stale, and tell a declared agent which door it should have used --
    all things an authorization failure normally makes somebody guess.
    """

    def __init__(self, assessment: Assessment, audience: str) -> None:
        why = "; ".join(assessment.reasons) or "no reason recorded"
        super().__init__(f"not admitted to {audience!r} ({assessment.verdict.value}): {why}")
        self.assessment = assessment
        self.audience = audience


class Nest:
    """One protected audience.

    `audience` is required and there is no default. A default audience is a
    skeleton key with a friendly name: every nest that inherited it would accept
    every other nest's attestations.
    """

    def __init__(self, audience: str, *, policy: Optional[Policy] = None,
                 key: Optional[Key] = None, seen: Optional[Seen] = None) -> None:
        if not audience:
            raise ValueError("a nest needs an audience -- the name of the door it guards")
        self.audience = audience
        self.policy = policy or Policy()
        self.key = key
        self.seen = seen

    # -- the two ways to ask ------------------------------------------------

    def admit(self, *, token: Optional[str] = None, evidence: Iterable[Evidence] = (),
              subject: Optional[str] = None, context: Optional[str] = None,
              now: Optional[float] = None) -> Assessment:
        """Assess this caller. Never raises for an ordinary refusal.

        `context` binds the answer to a specific THING -- this commit, this request
        body, this transfer. Leaving it None is not "any context": a token that
        carries one is refused here, by design, so an action-bound attestation can
        never be spent on an unbound door.
        """
        t = time.time() if now is None else now
        items: Sequence[Evidence] = tuple(evidence)

        if token:
            if self.key is None:
                return Assessment(
                    Verdict.UNKNOWN, None,
                    ("a token was presented but this nest holds no key to check it with "
                     "-- refusing rather than trusting an unverifiable claim",))
            try:
                att = verify(token, self.key, audience=self.audience, subject=subject,
                             context=context, now=t, seen=self.seen)
            except AttestationError as exc:
                return Assessment(Verdict.UNKNOWN, None, (f"attestation refused: {exc}",))
            return self._from_attestation(att, t)

        return assess(items, self.policy, now=t)

    def require(self, *, token: Optional[str] = None, evidence: Iterable[Evidence] = (),
                subject: Optional[str] = None, context: Optional[str] = None,
                now: Optional[float] = None) -> Assessment:
        """Assess, and raise NotAdmitted unless this door opens."""
        a = self.admit(token=token, evidence=evidence, subject=subject,
                       context=context, now=now)
        if not a.admitted(self.policy):
            raise NotAdmitted(a, self.audience)
        return a

    def door(self, *, token: Optional[str] = None, evidence: Iterable[Evidence] = (),
             subject: Optional[str] = None, context: Optional[str] = None,
             now: Optional[float] = None) -> str:
        """Which door this caller belongs at: "human", "agent" or "closed".

        Separate from `admit` because a surface that wants to SERVE an agent
        differently -- rate limits, a machine-readable response, an agent-only
        channel -- needs the answer even when its human door is shut.
        """
        a = self.admit(token=token, evidence=evidence, subject=subject,
                       context=context, now=now)
        if a.verdict is Verdict.HUMAN:
            return "human"
        if a.verdict is Verdict.AGENT:
            return "agent"
        return "closed"

    # -- issuing ------------------------------------------------------------

    def issue(self, subject: str, assessment: Assessment, *, ttl_s: float = 3600.0,
              method: str = "unspecified", context: Optional[str] = None,
              now: Optional[float] = None) -> str:
        """Write down a conclusion this nest reached, for later or elsewhere.

        Refuses to sign an UNKNOWN -- `attest.payload_for` enforces it, and this
        docstring repeats it because the tempting call site is "issue whatever we
        got and let the verifier decide", which produces a signed shrug that every
        downstream reader treats as a signed check.
        """
        if self.key is None:
            raise AttestationError("this nest holds no key, so it cannot issue")
        return mint(self.key, sub=subject, aud=self.audience, verdict=assessment.verdict,
                    score=assessment.score, ttl_s=ttl_s, method=method, ctx=context,
                    now=now)

    # -- internals ----------------------------------------------------------

    def _from_attestation(self, att: Attestation, now: float) -> Assessment:
        """A verified attestation, re-judged against THIS door.

        The issuer's `exp` is the issuer's opinion; `policy.max_age_s` is the
        door's, and the door's is not overridable by whoever minted the token --
        otherwise a permissive issuer silently sets every consumer's policy, which
        is how one long-lived credential ends up opening the payments page.
        """
        age = att.age_s(now)
        reasons = [f"attestation from {att.method or 'an unnamed check'}, {int(age)}s old"]
        if age > self.policy.max_age_s:
            reasons.append(
                f"older than this door's {int(self.policy.max_age_s)}s, even though the "
                "issuer had not expired it"
            )
            return Assessment(Verdict.UNKNOWN, att.score, tuple(reasons))
        if att.verdict is Verdict.HUMAN and att.score is not None \
                and att.score < self.policy.min_score:
            reasons.append(f"scored {att.score}, below this door's {self.policy.min_score}")
            return Assessment(Verdict.UNKNOWN, att.score, tuple(reasons))
        return Assessment(att.verdict, att.score, tuple(reasons))
