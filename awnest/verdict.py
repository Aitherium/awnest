"""The verdict plane: what the evidence adds up to, and what happens when it does not.

THE ONE DEFECT THIS MODULE EXISTS FOR
=====================================
Every human check ever written fails OPEN. Not because anyone decided it should,
but because "we could not tell" and "it is fine" arrive at the caller as the same
thing: an empty result, a None, a score of 0, a 500 somebody catches. The gate is
then a decoration that denies nobody, and it passes every test anyone writes for
it, because the tests assert that a bot is refused -- and a bot IS refused, right
up until the evaluator has a bad afternoon.

So the verdict type here has no member meaning "ok". It has HUMAN, AGENT and
UNKNOWN, and UNKNOWN is what you get from an absent evaluator, an unparseable
answer, a stale attestation, an empty evidence list, and a policy nobody
configured. Admission is granted by naming a verdict, never by failing to reach
one.

WHY "AGENT" IS A VERDICT AND NOT A FAILURE
==========================================
"Human or bot" is the wrong question and it makes the check worse. If the only
way through a door is to be human, every legitimate automation is taught to
imitate one, and you have spent your budget training the thing you are trying to
detect. A nest is not a wall: you know who is who, and there is a door for each.

A caller that DECLARES itself an agent is believed -- that is the whole point, an
honest declaration costs it the human door and buys it the agent door -- and a
caller that declares nothing is UNKNOWN, never "probably fine".

SCORED ZERO IS NOT UNSCORED
===========================
`Evidence.score is None` means nobody judged it. That is not a zero. Collapsing
the two is how an outage in the judge becomes a permanent silent accusation
against real people -- or, with the comparison the other way round, a permanent
silent pass. Unscored evidence is carried into the assessment's `reasons` and
counts toward NOTHING.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional, Sequence

__all__ = [
    "Verdict", "Evidence", "Policy", "Assessment", "assess",
    "DECLARED_AGENT", "DEFAULT_MIN_SCORE", "DEFAULT_MAX_AGE_S", "SCORE_RANGE",
]

#: Scores are 0-100. Stated as a constant because every source of evidence has to
#: be normalised INTO this range before it is comparable, and a judge that answers
#: 0-1 read as though it answered 0-100 is a real defect that has shipped before.
SCORE_RANGE = (0, 100)

#: A default that is a policy, not a magic number: below this, the evidence did
#: not distinguish the caller from an automated one.
DEFAULT_MIN_SCORE = 65

#: How long a human check stays good. NOT forever, and this is the interesting
#: half: an account held by a human on Tuesday can be sold, farmed or taken over
#: by Friday, so "verified once" is a fact about a MOMENT and it decays.
DEFAULT_MAX_AGE_S = 7 * 24 * 3600

#: The kind an honest automated caller uses to declare itself. A constant rather
#: than a literal at each site: this is the one kind whose spelling changes the
#: verdict, so a typo would silently demote an honest agent to UNKNOWN -- the
#: exact outcome that teaches automation to stop declaring.
DECLARED_AGENT = "declared_agent"


class Verdict(str, Enum):
    """What we concluded. There is deliberately no member meaning "allowed"."""

    HUMAN = "human"
    #: Declared, never detected. See the module docstring.
    AGENT = "agent"
    #: The check did not run, did not finish, or did not convince. One member for
    #: all three on purpose: a gate that treats "no answer" differently from "a bad
    #: answer" grows a path where an outage is more permissive than a bot.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Evidence:
    """One signal about one caller.

    `score is None` means NOT JUDGED -- see the module docstring. `at` is when the
    signal was produced, not when it was read, because a five-day-old judgement
    read one second ago is five days old.
    """

    kind: str
    score: Optional[int] = None
    at: float = field(default_factory=time.time)
    source: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("evidence needs a kind")
        if self.score is not None:
            lo, hi = SCORE_RANGE
            if not isinstance(self.score, int) or isinstance(self.score, bool) \
                    or not (lo <= self.score <= hi):
                raise ValueError(
                    f"score must be an int in {SCORE_RANGE}, or None for 'not judged'; "
                    f"got {self.score!r}. A judge that answers 0-1 must be normalised "
                    "here, not compared as though it answered 0-100."
                )


@dataclass(frozen=True)
class Policy:
    """What this particular door requires. Every default is the strict one."""

    min_score: int = DEFAULT_MIN_SCORE
    max_age_s: float = DEFAULT_MAX_AGE_S
    #: How many independent qualifying signals are needed. Above 1, one compromised
    #: evaluator is no longer sufficient on its own.
    min_signals: int = 1
    #: Does this door admit a declared agent? Default False: an agent-friendly door
    #: is a decision somebody makes, not a default somebody inherits.
    allow_agents: bool = False

    def __post_init__(self) -> None:
        lo, hi = SCORE_RANGE
        if not (lo <= self.min_score <= hi):
            raise ValueError(f"min_score must be within {SCORE_RANGE}")
        if self.max_age_s <= 0:
            raise ValueError(
                "max_age_s must be positive -- a non-positive age admits nobody, which "
                "reads as a broken gate rather than a strict one"
            )
        if self.min_signals < 1:
            raise ValueError("min_signals must be at least 1")


@dataclass(frozen=True)
class Assessment:
    """The conclusion, plus why -- including what was discarded and for what reason.

    `reasons` is not decoration. A decision nobody can explain becomes a debugging
    session every time it is wrong, and a human refused by a silent gate has no way
    to learn that their check simply went stale.
    """

    verdict: Verdict
    score: Optional[int]
    reasons: tuple[str, ...] = ()
    used: tuple[Evidence, ...] = ()

    @property
    def is_human(self) -> bool:
        return self.verdict is Verdict.HUMAN

    def admitted(self, policy: Policy) -> bool:
        """Does this assessment open THIS door?

        A method taking the door, never a property: `if a.admitted:` reads as a
        general permission, and there is no such thing -- an agent-friendly door
        and a humans-only door disagree about the same assessment.
        """
        if self.verdict is Verdict.HUMAN:
            return True
        if self.verdict is Verdict.AGENT:
            return policy.allow_agents
        return False


def assess(evidence: Iterable[Evidence], policy: Optional[Policy] = None,
           *, now: Optional[float] = None) -> Assessment:
    """Fold evidence into one verdict. Pure -- no clock beyond `now`, no I/O.

    The order of the rules is load-bearing:

    1. No evidence at all is UNKNOWN. Not "nothing against them, let them in".
    2. A DECLARED agent is AGENT, before any scoring. Scoring a caller that told
       you what it is wastes a judge call and, worse, occasionally decides it is
       human -- which makes an honest declaration a worse outcome than a silent
       one, and honesty has to be the cheaper path or nobody takes it.
    3. Everything else must EARN it: fresh enough, judged at all, and at or above
       this door's threshold, in `min_signals` independent pieces.
    """
    pol = policy or Policy()
    t = time.time() if now is None else now
    items: Sequence[Evidence] = tuple(evidence)

    if not items:
        return Assessment(Verdict.UNKNOWN, None, ("no evidence was presented",))

    declared = [e for e in items if e.kind == DECLARED_AGENT]
    if declared:
        return Assessment(
            Verdict.AGENT, None,
            (f"caller declared itself an agent ({declared[0].source or 'unnamed'})",),
            tuple(declared),
        )

    reasons: list[str] = []
    qualifying: list[Evidence] = []
    for e in items:
        age = t - e.at
        if e.score is None:
            reasons.append(f"{e.kind}: not judged -- carries no weight, and is not a zero")
            continue
        if age < 0:
            # A signal from the future is a clock problem or a forged timestamp.
            # Either way it is not evidence, and quietly accepting it makes the
            # expiry rule below optional for anyone who can set a timestamp.
            reasons.append(f"{e.kind}: timestamped in the future -- refused, not aged")
            continue
        if age > pol.max_age_s:
            reasons.append(
                f"{e.kind}: {int(age)}s old, past this door's {int(pol.max_age_s)}s -- "
                "a human check is a fact about a moment"
            )
            continue
        if e.score < pol.min_score:
            reasons.append(f"{e.kind}: scored {e.score}, below {pol.min_score}")
            continue
        qualifying.append(e)

    if len(qualifying) < pol.min_signals:
        reasons.append(f"{len(qualifying)} qualifying signal(s), {pol.min_signals} required")
        return Assessment(Verdict.UNKNOWN, None, tuple(reasons), tuple(qualifying))

    scores = [e.score for e in qualifying if e.score is not None]
    # The LOWEST qualifying score, not the mean. A mean lets one confident signal
    # carry a weak one over the line, which is the shape every evidence-stacking
    # bypass takes.
    worst = min(scores)
    reasons.append(f"{len(qualifying)} signal(s) at or above {pol.min_score}; reporting the lowest")
    return Assessment(Verdict.HUMAN, worst, tuple(reasons), tuple(qualifying))
