"""The challenge bank -- questions whose honest answers are hard to fake, and the
strict reading of whatever judged them.

WHY NOT A PUZZLE
================
CAPTCHA asks a machine-solvable question and charges the cost to the human. It is
hostile to the people it exists to serve -- worst to the ones with poor sight,
poor motor control, a slow connection, or a screen reader -- and the machines beat
it, so the only party reliably filtered is the customer. A check that a human
finds unpleasant and a bot finds cheap is exactly backwards.

These challenges instead ask for something a person HAS and a model does not: a
particular life. Not knowledge, not reasoning, not speed -- specific embodied
memory, felt time, moral weight, a real reaction to being asked. A model answers
all of them fluently and answers them like a composite of everyone, which is the
signal.

WHAT THIS IS NOT
================
It is not proof. A determined operator can pay a person to answer, or feed a model
a real diary. Every claim about strength here is bounded by that, and the honest
framing is COST: it raises the price of a fake account from free to
"a human minute per account", which is the entire game for spam economics. If you
need more than that, stack another signal -- the verdict plane takes several and
reports the WEAKEST, so adding one can never weaken the result.

Nothing here scores anything. Scoring needs a judge (a model, a person, a service)
and this module refuses to pretend otherwise -- the strict parser below is where
that judgement is admitted, and it refuses far more than it accepts.
"""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

__all__ = [
    "Challenge", "CHALLENGES", "CATEGORIES", "select", "check_answers",
    "judge_prompt", "parse_judgement", "Judgement",
    "ANSWER_MIN_CHARS", "ANSWER_MAX_CHARS", "JUDGEMENT_FIELDS",
]

#: Short answers carry no signal -- "yes", "idk", a single word are equally
#: consistent with a person and a script, so accepting them is accepting nothing.
ANSWER_MIN_CHARS = 20
#: And a wall of text is a pasted essay, not a reply. Both bounds are refusals
#: made HERE, before a judge is paid to read them.
ANSWER_MAX_CHARS = 2000


@dataclass(frozen=True)
class Challenge:
    """One question, plus what a reader should look for. `criteria` is for the
    JUDGE and must never be shown to the person answering: published, it is an
    instruction sheet for passing."""

    id: str
    category: str
    prompt: str
    criteria: str

    def public(self) -> dict[str, str]:
        """Exactly what a caller may be shown. The criteria are not in here, and
        that omission is the point -- see the class docstring."""
        return {"id": self.id, "category": self.category, "prompt": self.prompt}


CHALLENGES: tuple[Challenge, ...] = (
    Challenge(
        "exp_memory", "experiential",
        "Describe a vivid memory from childhood -- what you saw, smelled, or felt "
        "physically. Be specific and personal rather than general.",
        "Look for sensory detail that reads as lived: a particular smell, texture, "
        "temperature, the emotion tied to a place. Human recall is fragmentary and "
        "uneven -- one detail is impossibly sharp and the rest is missing. A complete, "
        "well-shaped narrative with evenly distributed detail is the tell.",
    ),
    Challenge(
        "body_awareness", "embodied",
        "What does it feel like in your body in the seconds before you sneeze? "
        "Describe the physical sensation as precisely as you can.",
        "Look for proprioceptive, first-person detail -- the tickle, the involuntary "
        "build, the urge, the failed sneeze. A textbook or medical description of the "
        "reflex is an answer about sneezing rather than an answer from inside one.",
    ),
    Challenge(
        "time_perception", "temporal",
        "Describe a moment when time seemed to slow down or speed up. What was "
        "happening, and why do you think it felt that way?",
        "Look for a specific emotional context that distorts time -- danger, flow, "
        "grief, boredom, joy -- tied to one concrete event. A general reflection on "
        "the philosophy of time is the failure mode.",
    ),
    Challenge(
        "moral_weight", "ethical",
        "Tell me about something you did that you knew was wrong at the time. Why did "
        "you do it? Do you still think about it?",
        "Look for genuine complexity: rationalisation, lingering guilt, an unflattering "
        "detail the writer did not have to include. Sanitised examples, tidy morals, or "
        "a refusal to answer all score low. Ambiguity scores high.",
    ),
    Challenge(
        "absurd_creative", "creative",
        "Invent a word that does not exist and define it. Then use it in a sentence "
        "about your Tuesday.",
        "Look for a word shaped by personal sound preference rather than one that is "
        "linguistically well-formed, and for a sentence about a real-feeling mundane "
        "day. A plausible neologism attached to a generic day is the tell.",
    ),
    Challenge(
        "emotional_now", "emotional",
        "What are you feeling right now, honestly? Not what you think you should feel "
        "-- what is actually going on as you read this.",
        "Look for present-tense self-awareness, contradiction, or something mildly "
        "unflattering. Real feelings are mixed and often boring. Uniformly positive or "
        "neatly categorised emotion is the failure mode.",
    ),
    Challenge(
        "meta_test", "metacognitive",
        "You are taking a test to prove you are a person. How does that make you feel? "
        "Weird, stupid, reasonable? Be honest.",
        "Look for a real reaction to the situation -- irritation, amusement, resignation, "
        "a joke at the test's expense. Earnest cooperation with no reaction to the "
        "absurdity of the request is the tell.",
    ),
)

CATEGORIES: tuple[str, ...] = tuple(dict.fromkeys(c.category for c in CHALLENGES))


def select(n: int = 3, *, rng: Optional[random.Random] = None) -> tuple[Challenge, ...]:
    """Pick `n` challenges from DIFFERENT categories.

    Different categories, never `sample()` over the flat bank: two embodied
    questions in one set are one question asked twice, and a set that can repeat a
    category is measurably easier to prepare for.
    """
    if n < 1:
        raise ValueError("select() needs at least one challenge")
    if n > len(CATEGORIES):
        raise ValueError(
            f"only {len(CATEGORIES)} categories exist; asking for {n} would repeat one, "
            "which is the same question twice rather than a longer test"
        )
    r = rng or random.SystemRandom()
    cats = list(CATEGORIES)
    r.shuffle(cats)
    out = []
    for cat in cats[:n]:
        pool = [c for c in CHALLENGES if c.category == cat]
        out.append(pool[r.randrange(len(pool))])
    return tuple(out)


def check_answers(challenges: Sequence[Challenge], answers: Mapping[str, str]) -> None:
    """Refuse locally what a judge would only refuse expensively. Raises ValueError.

    Returns None on success rather than a bool: `if check_answers(...)` on a
    bool-returning validator is the shape that admits everything the day somebody
    inverts it, and this one is called from a gate.
    """
    if not challenges:
        raise ValueError("no challenges were issued -- there is nothing to answer")
    for c in challenges:
        if c.id not in answers:
            raise ValueError(f"missing answer for {c.id}")
        a = (answers[c.id] or "").strip()
        if len(a) < ANSWER_MIN_CHARS:
            raise ValueError(
                f"answer for {c.id} is {len(a)} chars, under {ANSWER_MIN_CHARS}"
            )
        if len(a) > ANSWER_MAX_CHARS:
            raise ValueError(
                f"answer for {c.id} is {len(a)} chars, over {ANSWER_MAX_CHARS}"
            )
    extra = [k for k in answers if k not in {c.id for c in challenges}]
    if extra:
        # Not pedantry: an answer to a challenge that was not issued means the
        # caller is replaying a set, or a session got crossed with another one.
        raise ValueError(f"answers include challenges that were not issued: {extra}")


def judge_prompt(challenges: Sequence[Challenge], answers: Mapping[str, str]) -> str:
    """Build the evaluation prompt. Pure, so it is testable with no model."""
    check_answers(challenges, answers)
    parts = []
    for c in challenges:
        parts.append(
            f"## Challenge [{c.id}] -- {c.category}\n"
            f"Question: {c.prompt}\n"
            f"Answer:\n{answers[c.id].strip()}\n"
            f"What to look for:\n{c.criteria}\n"
        )
    return (
        "Judge whether these answers were written by a person drawing on a real life, "
        "or produced by a language model. Score each answer 0-100 for authenticity, "
        "where 100 is certainly a person and 0 is certainly generated.\n\n"
        "Weigh: sensory specificity; emotion that is mixed or unflattering rather than "
        "tidy; detail specific to one life rather than to everyone's; imperfection, "
        "self-correction and rambling; a real reaction to being asked.\n\n"
        "Reply with JSON only, no prose around it:\n"
        '{"scores": {"<challenge_id>": <0-100>, ...}, "overall": <0-100>, '
        '"verdict": "human" | "uncertain" | "likely_bot", "reasoning": "<one or two sentences>"}\n\n'
        + "\n".join(parts)
    )


#: EXACTLY what a judgement must contain. A constant the self-test asserts, because
#: the tempting bug is `data.get("overall", 100)` -- a default that turns an
#: unparseable answer into a perfect score.
JUDGEMENT_FIELDS = ("scores", "overall", "verdict", "reasoning")

_VERDICTS = ("human", "uncertain", "likely_bot")


@dataclass(frozen=True)
class Judgement:
    """A parsed, validated judgement. Only ever built by `parse_judgement`."""

    scores: dict[str, int]
    overall: int
    verdict: str
    reasoning: str


def parse_judgement(text: str, *, expect: Optional[Iterable[str]] = None) -> Judgement:
    """Read a judge's reply strictly. Raises ValueError rather than guessing.

    THE NORMALISATION TRAP, which is the reason this function exists at all:
    judges disagree about scale. Some answer 0-100, some 0-1. The obvious fix --
    "if it is <= 1, multiply by 100" -- is a silent catastrophe, because a score of
    exactly 1 on a 0-100 scale means ALMOST CERTAINLY A BOT and gets promoted to
    100, ALMOST CERTAINLY A PERSON. The two worst possible readings of one number,
    and no error anywhere.

    So the scale is fixed at 0-100, stated in the prompt, and enforced twice: a
    value outside the range is refused, and so is a FRACTIONAL one. `0.9` is the
    interesting case -- it is inside 0-100 and therefore survives a range check,
    while being overwhelmingly likely to mean 90 on the other scale. Both readings
    are defensible, which is exactly why this must not choose between them.
    Integral floats (`80.0`) are fine; the ambiguity is in the fraction, not the
    type. A refused judgement costs one retry; a silently inverted one admits every
    bot that scored badly enough.
    """
    if not (text or "").strip():
        raise ValueError("judge returned nothing -- that is not a score of zero")
    raw = text.strip()
    # Models fence JSON in markdown even when told not to. Tolerating the fence is
    # not laxity: refusing it would make this reject correct judgements and push a
    # caller toward a looser parser somewhere else.
    fence = re.search(r"```(?:json)?\s*(.+?)```", raw, re.S)
    if fence:
        raw = fence.group(1).strip()
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("judge reply contains no JSON object")
        raw = raw[start:end + 1]
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"judge reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("judge reply is not a JSON object")

    missing = [f for f in JUDGEMENT_FIELDS if f not in data]
    if missing:
        raise ValueError(f"judge reply is missing {missing} -- refusing to supply a default")

    if not isinstance(data["scores"], dict) or not data["scores"]:
        raise ValueError("judge reply has no per-challenge scores")
    scores: dict[str, int] = {}
    for k, v in data["scores"].items():
        scores[str(k)] = _score(v, f"scores[{k}]")
    overall = _score(data["overall"], "overall")

    verdict = str(data["verdict"]).strip().lower()
    if verdict not in _VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}; expected one of {_VERDICTS}")

    if expect is not None:
        wanted = set(expect)
        got = set(scores)
        if wanted - got:
            # A judge that scored two of three challenges has not judged the
            # submission. Averaging what came back would quietly drop the answer
            # the model found hardest to read, which is the informative one.
            raise ValueError(f"judge did not score {sorted(wanted - got)}")

    return Judgement(scores, overall, verdict, str(data["reasoning"]))


def _score(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} is {value!r}, not a number")
    v = float(value)
    if not (0 <= v <= 100):
        raise ValueError(
            f"{where} is {value}, outside 0-100. Not rescaled on purpose -- see "
            "parse_judgement's docstring; guessing the scale inverts the worst scores."
        )
    if v != int(v):
        raise ValueError(
            f"{where} is {value}, a fraction. On this scale that is a near-certain bot; "
            "on the 0-1 scale it is a near-certain person. Refusing rather than picking "
            "one -- ask the judge again for an integer 0-100."
        )
    return int(v)
