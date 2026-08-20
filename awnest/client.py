"""A portable client for a humanity-check-shaped service.

WHY A CLIENT AND NOT A LIFT
===========================
The identity services that run checks like this are tens of thousands of lines
wired to a directory, a session store, a judge and an event bus. Lifting one into
a package produces something that raises ModuleNotFoundError on a stranger's
machine while reading as authoritative -- a broken package is worse than an absent
one. The wire contract is the portable part, so that is what ships.

WHAT "SHAPED" MEANS -- read off a running service, not invented:

    POST /auth/me/verify-humanity/challenge   -> {session_id, challenges[], expires_at}
    POST /auth/me/verify-humanity/submit      -> {humanity_verified, humanity_score,
                                                  humanity_verdict, ...}

THE TRAP THIS CLIENT EXISTS FOR
===============================
The session id travels in a HEADER (`X-Verification-Session`), not in the body,
while the answers travel in the body. That split is invisible from the response
shape and is the single easiest thing to get wrong: put the session in the body
and the service replies 422 about a missing header, which reads as "the API
changed" rather than "you put it in the wrong place". The header name and the body
fields are therefore constants the self-test asserts as EXACT tuples, not
literals sprinkled through the code.

AND THE ONE THAT MATTERS MORE -- 503 IS NOT A LOW SCORE
=======================================================
When the judge behind such a service is unreachable, a correct implementation
returns 503 and records NOTHING. A client that turns that into
`{"verified": False}` has converted an outage into a permanent accusation against
a real person -- and the caller cannot tell the two apart, because "we could not
check you" and "we checked you and you failed" arrive as the same falsy value.
So a transport failure and a 503 both RAISE here. Refusal is a verdict; silence is
not.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

import httpx

from awnest.challenge import Challenge
from awnest.verdict import Evidence

__all__ = [
    "HumanityClient", "NestClientError", "ChallengeSet",
    "SUBMIT_FIELDS", "SESSION_HEADER", "CHALLENGE_PATH", "SUBMIT_PATH",
]

DEFAULT_TIMEOUT = 60.0

#: The route pair. Constants so a deployment that mounts them under a prefix
#: overrides one thing, rather than a caller string-building two URLs.
CHALLENGE_PATH = "/auth/me/verify-humanity/challenge"
SUBMIT_PATH = "/auth/me/verify-humanity/submit"

#: EXACTLY the submit body. See the module docstring: `session_id` is NOT in here.
SUBMIT_FIELDS = ("challenge_ids", "answers")

#: ...it is here.
SESSION_HEADER = "X-Verification-Session"


class NestClientError(RuntimeError):
    """The service refused, could not answer, or answered something unreadable.

    Raised, never returned as an unverified result. See the module docstring.
    """


class ChallengeSet:
    """One issued set: the questions, and the session they belong to."""

    def __init__(self, session_id: str, challenges: Sequence[Mapping[str, Any]],
                 expires_at: str = "") -> None:
        if not session_id:
            raise NestClientError("service issued a challenge set with no session id")
        if not challenges:
            raise NestClientError("service issued a challenge set with no challenges")
        self.session_id = session_id
        self.expires_at = expires_at
        #: `criteria` is deliberately absent -- the service does not send it, and a
        #: client that invented one would be publishing the answer key.
        self.challenges = tuple(
            Challenge(id=str(c["id"]), category=str(c.get("category", "")),
                      prompt=str(c["prompt"]), criteria="")
            for c in challenges
        )

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self.challenges)


def submit_body(challenge_ids: Sequence[str], answers: Mapping[str, str]) -> dict:
    """The submit body. Pure, so the field set is testable with no service."""
    ids = tuple(challenge_ids)
    if not ids:
        raise ValueError("submit needs the ids of the challenges that were issued")
    missing = [i for i in ids if i not in answers]
    if missing:
        raise ValueError(f"no answer supplied for {missing}")
    return {"challenge_ids": list(ids), "answers": {k: answers[k] for k in ids}}


class HumanityClient:
    """Talks to one humanity-check-shaped service.

    The origin is never guessed. A verification client that falls back to some
    default endpoint sends a person's most personal answers -- childhood memories,
    a thing they regret -- to a host nobody chose.
    """

    def __init__(self, base_url: str, *, token: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 client: Optional[httpx.Client] = None) -> None:
        if not base_url:
            raise ValueError("base_url is required; this client guesses no origin")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client

    def _headers(self, extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        # No token means NO header. An empty `Bearer ` is rejected differently from
        # an absent one, which sends you debugging the wrong side of the call.
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def _post(self, path: str, body: dict, headers: Optional[Mapping[str, str]] = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            if self._client is not None:
                res = self._client.post(url, json=body, headers=self._headers(headers))
            else:
                with httpx.Client(timeout=self.timeout) as c:
                    res = c.post(url, json=body, headers=self._headers(headers))
        except httpx.HTTPError as exc:
            raise NestClientError(f"{url} unreachable: {exc}") from exc
        if res.status_code == 503:
            raise NestClientError(
                f"{url} could not evaluate the submission (503). Nothing was recorded -- "
                "this is an outage, not a failed check, and must not be read as one."
            )
        if res.status_code >= 400:
            raise NestClientError(f"{url} refused with {res.status_code}: {res.text[:300]}")
        try:
            data = res.json()
        except ValueError as exc:
            raise NestClientError(f"{url} did not return JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise NestClientError(f"{url} returned {type(data).__name__}, expected an object")
        return data

    def challenge(self) -> ChallengeSet:
        """Ask for a set of challenges."""
        data = self._post(CHALLENGE_PATH, {})
        try:
            return ChallengeSet(str(data["session_id"]), data["challenges"],
                                str(data.get("expires_at", "")))
        except KeyError as exc:
            raise NestClientError(f"challenge response is missing {exc}") from exc

    def submit(self, issued: ChallengeSet, answers: Mapping[str, str]) -> Evidence:
        """Submit answers and return the judgement AS EVIDENCE.

        Evidence rather than a bool: the caller's policy decides what a score of 71
        is worth at its own door, and the freshness of the judgement travels with
        it. A bool here would strip both and be believed forever.
        """
        body = submit_body(issued.ids, answers)
        data = self._post(SUBMIT_PATH, body, {SESSION_HEADER: issued.session_id})
        if "humanity_score" not in data:
            raise NestClientError(
                "submit response carries no score -- refusing to infer one from "
                f"{sorted(data)[:8]}"
            )
        score = data["humanity_score"]
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            raise NestClientError(f"humanity_score is {score!r}, not a number")
        return Evidence(
            kind="judged_challenges",
            score=int(round(float(score))),
            source=self.base_url,
            detail=str(data.get("humanity_verdict", "")),
        )
