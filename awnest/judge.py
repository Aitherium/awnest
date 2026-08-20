"""Scoring the answers with whatever model you already have.

This speaks the OpenAI-compatible `/v1/chat/completions` shape, which is the one
thing every local runtime, gateway and hosted API agrees on -- so the judge can be
a model on your own machine, and for this particular job it probably should be.

A PRIVACY NOTE THAT IS PART OF THE DESIGN, NOT A DISCLAIMER
===========================================================
These challenges deliberately ask for the most personal material a stranger will
ever type into your product: a childhood memory, a thing they regret, what they
are feeling right now. Posting that to a third-party API is a decision about
somebody else's private life, and the reason `base_url` has no default is that
nobody should ever make that decision by inheriting one.

WHAT IT WILL NOT DO
===================
It will not return a score it did not receive. A dead endpoint, a truncated reply,
a model that answered in prose, a JSON object missing `overall` -- all raise. The
alternative is the defect this whole package is shaped around: an evaluator that
is down, returning zero, and a gate that reads zero as a judgement.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

import httpx

from awnest.challenge import Challenge, Judgement, judge_prompt, parse_judgement
from awnest.verdict import Evidence

__all__ = ["JudgeError", "score_answers", "JUDGE_KIND", "SYSTEM_PROMPT"]

#: The evidence kind a model-scored challenge set produces. Named as a constant
#: because a policy that requires two INDEPENDENT signals has to be able to tell
#: two model scorings apart from a model plus something else.
JUDGE_KIND = "judged_challenges"

SYSTEM_PROMPT = (
    "You evaluate whether text was written by a person drawing on a real life or "
    "produced by a language model. You reply with a single JSON object and no other text."
)

DEFAULT_TIMEOUT = 120.0


class JudgeError(RuntimeError):
    """The judge could not be reached, or did not return a judgement."""


def score_answers(base_url: str, challenges: Sequence[Challenge],
                  answers: Mapping[str, str], *, model: str,
                  token: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT,
                  temperature: float = 0.0,
                  client: Optional[httpx.Client] = None) -> tuple[Evidence, Judgement]:
    """Score one submission. Returns (evidence, the full judgement) or raises.

    Returns both because they answer different questions: the Evidence is what a
    policy consumes, and the Judgement is what you show a person who wants to know
    why. Handing back only the number is how a refusal becomes unexplainable.
    """
    if not base_url:
        raise ValueError("base_url is required -- see this module's privacy note")
    if not model:
        raise ValueError("model is required; a judge nobody chose is a judge nobody can audit")

    prompt = judge_prompt(challenges, answers)   # validates the answers first
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        # Low, not zero-by-accident: a judgement that changes between two identical
        # submissions is one nobody can appeal.
        "temperature": temperature,
        "max_tokens": 600,
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    try:
        if client is not None:
            res = client.post(url, json=body, headers=headers)
        else:
            with httpx.Client(timeout=timeout) as c:
                res = c.post(url, json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise JudgeError(f"judge at {url} unreachable: {exc}") from exc
    if res.status_code >= 400:
        raise JudgeError(f"judge at {url} refused with {res.status_code}: {res.text[:300]}")

    try:
        data: Any = res.json()
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise JudgeError(f"judge reply is not a chat completion: {exc}") from exc

    try:
        judgement = parse_judgement(content, expect=[c.id for c in challenges])
    except ValueError as exc:
        # Deliberately not retried here with a looser parser. A judgement we had to
        # guess at is not a judgement, and the caller can retry knowing it did.
        raise JudgeError(f"judge did not return a usable judgement: {exc}") from exc

    return (
        Evidence(kind=JUDGE_KIND, score=judgement.overall,
                 source=f"{base_url.rstrip('/')}::{model}", detail=judgement.verdict),
        judgement,
    )
