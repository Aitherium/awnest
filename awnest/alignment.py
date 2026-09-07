"""The alignment door: a fun human check that attests WHO took it and WHAT they got.

WHAT THIS DOOR IS
=================
The rest of awnest asks "is there a person here" and refuses to guess. This door
asks something friendlier -- "which of the nine is you?" -- and answers with the
classic D&D-style two-axis chart. It is deliberately NOT a puzzle and NOT a
judge-graded challenge: scoring is deterministic, in this module, with no model
and no service. You can read the whole thing and still not game it in the way
that matters, because of the second half:

THE ATTESTATION IS THE POINT, NOT THE SCORE
============================================
A badge you can screenshot is a picture. A badge backed by an awnest
attestation is a CLAIM: this exact identity (sub), at this exact moment (iat),
for this exact door (aud), took this quiz and got THIS result (ctx). The ctx is
bound to the result verbatim -- alignment id AND both axis scores -- so a badge
cannot be relabeled from "chaotic good" to "lawful good" without invalidating
the token. Verification is offline and symmetric: the badge carries its own
binding, and a verifier that does not name the same context refuses it.

WHAT THE VERDICT DOES AND DOES NOT MEAN
=======================================
The attestation records verdict=HUMAN. Read that honestly: it means "the claim
arrived from an authenticated identity on an interactive session", not "a
scientifically verified human took this". This module does not judge humanity
and never pretends to -- a bot with a session could take the quiz too. What the
attestation DOES prove, verifiably and offline, is that the badge is not a
screenshot: it is a signed statement by the door that issued it, bound to one
identity, one result, and one use.

THE WEIGHTS ARE NOT SECRET, BUT THE PROTOCOL DOES NOT HAND THEM OUT
==================================================================
`questions_public()` omits the weights the same way `challenge.public()`
omits the judge's criteria: shipping the answer key with the questions is an
instruction sheet for passing. The scoring source is open like everything else
here -- the point is the attestation, not the secrecy.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from awnest.attest import Attestation, Key, mint, verify
from awnest.audience import audience
from awnest.verdict import Verdict

__all__ = [
    "ALIGNMENT_AUDIENCE", "ALIGNMENTS", "ALIGNMENT_IDS", "BADGE_TTL_S",
    "NEUTRAL_BAND", "QUIZ_VERSION", "QUESTIONS", "AlignmentResult",
    "Question", "Option", "badge_svg", "chart_svg", "mint_badge",
    "parse_result_context", "questions_public", "result_context",
    "score_answers", "verify_badge",
]

#: The one door every alignment badge is for. A badge minted for another door
#: is a badge nobody's page will show -- and a badge shown without this door's
#: key verifies for nothing. `action` is the audience kind for "one specific
#: action" (see awnest.audience); this is that action.
ALIGNMENT_AUDIENCE = audience("action", "alignment_badge")

#: The quiz is versioned so a result context names WHICH bank produced it. A
#: v2 rebalance must not verify against a v1 token -- the ctx carries the
#: version, so the binding survives the rebalance the same way it survives a
#: relabel: by refusing.
QUIZ_VERSION = "v1"

#: How far from zero an axis score must be to count as aligned. Inside this
#: band the answers are genuinely mixed and the axis reads NEUTRAL. A
#: zero-sum answer set MUST land here and a strongly consistent one MUST NOT;
#: the boundary is inclusive (exactly 0.15 is neutral), stated so the tests
#: can pin it.
NEUTRAL_BAND = 0.15

#: A badge is a wall decoration, not a session credential -- one year is the
#: honest lifetime, and re-taking the quiz refreshes it. The verdict plane's
#: short TTLs are for doors; this door is a keepsake.
BADGE_TTL_S = 365 * 24 * 3600


@dataclass(frozen=True)
class Option:
    """One answer to one question, and what it says about you. The weights are
    on the ORDER axis (positive = lawful, negative = chaotic) and the MORAL
    axis (positive = good, negative = evil), each in [-1, 1]."""

    id: str
    text: str
    law: float
    good: float

    def public(self) -> dict[str, str]:
        """What a caller may be shown: the answer, never the weights."""
        return {"id": self.id, "text": self.text}


@dataclass(frozen=True)
class Question:
    """One scenario, addressed to an adventurer. `options` is an ordered
    tuple; the ids, not positions, are what scoring reads, so reordering the
    options never changes a result."""

    id: str
    prompt: str
    options: tuple[Option, ...]

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "options": [o.public() for o in self.options],
        }


@dataclass(frozen=True)
class AlignmentDef:
    """One cell of the classic chart: an id, a name, a look, and a line."""

    id: str
    name: str
    emoji: str
    color: str
    flavor: str


#: The nine classic cells. `id` is what travels in attestations; `name` is what
#: a human reads; `flavor` is the one-line personality the badge carries.
ALIGNMENTS: dict[str, AlignmentDef] = {
    d.id: d for d in (
        AlignmentDef("lawful_good", "Lawful Good", "🛡️", "#2f6fd0",
                     "The paladin's path: order in service of what is right."),
        AlignmentDef("neutral_good", "Neutral Good", "🕊️", "#2e9e6b",
                     "The protector: kindness first, rules second."),
        AlignmentDef("chaotic_good", "Chaotic Good", "🦊", "#d97b2b",
                     "The rebel with a cause: freedom, and a helping hand."),
        AlignmentDef("lawful_neutral", "Lawful Neutral", "⚖️", "#6b7a99",
                     "The judge: the law is the law, and that is a feature."),
        AlignmentDef("true_neutral", "True Neutral", "🌀", "#8a7bb0",
                     "The druid: balance is not indecision."),
        AlignmentDef("chaotic_neutral", "Chaotic Neutral", "🎲", "#3aa8a0",
                     "The trickster: whim is a perfectly good philosophy."),
        AlignmentDef("lawful_evil", "Lawful Evil", "🗡️", "#5a3d8a",
                     "The tyrant: the world needs an iron hand."),
        AlignmentDef("neutral_evil", "Neutral Evil", "🐍", "#94404a",
                     "The schemer: everyone has a price."),
        AlignmentDef("chaotic_evil", "Chaotic Evil", "💀", "#a02626",
                     "The destroyer: if it burns, it was probably lying."),
    )
}

ALIGNMENT_IDS: tuple[str, ...] = tuple(ALIGNMENTS)


@dataclass(frozen=True)
class AlignmentResult:
    """What the answers add up to. Scores are floats in [-1, 1] on both axes;
    buckets are the three-way split of each axis; `alignment` is the cell id."""

    order_score: float
    moral_score: float
    order_bucket: str    # "lawful" | "neutral" | "chaotic"
    moral_bucket: str    # "good" | "neutral" | "evil"
    alignment: str

    def public(self) -> dict[str, Any]:
        return {
            "alignment": self.alignment,
            "name": ALIGNMENTS[self.alignment].name,
            "emoji": ALIGNMENTS[self.alignment].emoji,
            "flavor": ALIGNMENTS[self.alignment].flavor,
            "law": self.order_score,
            "good": self.moral_score,
            "law_axis": self.order_bucket,
            "good_axis": self.moral_bucket,
            "quiz": QUIZ_VERSION,
        }


QUESTIONS: tuple[Question, ...] = (
    Question(
        "q01", "On the road you find a fat coinpurse with the owner's name "
               "stitched inside.",
        (
            Option("q01_a", "Return it, unopened, to its owner.", 0.75, 0.75),
            Option("q01_b", "Take it to the town guard; they will sort it out.",
                   0.75, 0.25),
            Option("q01_c", "Find the owner yourself, by your own rules -- "
                            "no guards.", -0.75, 0.75),
            Option("q01_d", "Keep it. The road gave it to you.", -0.75, -0.5),
        ),
    ),
    Question(
        "q02", "A merchant cuts the line at the only well in a drought town.",
        (
            Option("q02_a", "Wordless, you tap their shoulder and point to "
                            "the end.", 0.75, 0.25),
            Option("q02_b", "You wait. It is a well, not a war.", 0.0, 0.25),
            Option("q02_c", "You cut in front of them right back.", -0.75, -0.25),
            Option("q02_d", "You deliver a lecture on civic virtue that makes "
                            "everyone uncomfortable.", 0.5, -0.25),
        ),
    ),
    Question(
        "q03", "Your captain orders you to tell the innkeeper her roof 'is "
               "fine' when it clearly is not -- he is cheap and she is your "
               "friend.",
        (
            Option("q03_a", "You tell her the truth. The captain can find "
                            "another liar.", -0.5, 0.75),
            Option("q03_b", "You obey. Orders are orders.", 0.75, -0.25),
            Option("q03_c", "You tell her the truth, and file a formal "
                            "complaint against the captain.", 0.75, 0.5),
            Option("q03_d", "You agree with the captain loudly -- and simply "
                            "forget to mention it to her at all.", -0.25, 0.5),
        ),
    ),
    Question(
        "q04", "A contract you signed has a loophole that lets you break it "
               "without penalty. Breaking it strands a village mid-harvest.",
        (
            Option("q04_a", "A contract is a contract. You honor it.", 0.75, 0.5),
            Option("q04_b", "You take the loophole. They should have read the "
                            "fine print.", -0.75, -0.5),
            Option("q04_c", "You break the contract openly and work the "
                            "harvest free.", -0.5, 0.75),
            Option("q04_d", "You take the loophole -- a deal is a deal, and "
                            "you were the one who read it.", 0.75, -0.5),
        ),
    ),
    Question(
        "q05", "A sealed passage shaves three days off the quest. The sigil "
               "on the door says it is cursed.",
        (
            Option("q05_a", "You open it anyway. Curses are a rumor problem.",
                   -0.75, 0.0),
            Option("q05_b", "You take the long road. Three days is cheap for "
                            "a soul.", 0.0, 0.5),
            Option("q05_c", "You open it -- and leave a warning for the next "
                            "party.", -0.25, 0.75),
            Option("q05_d", "You ask the village elder about the sigil first. "
                            "Knowledge is a lantern.", 0.5, 0.25),
        ),
    ),
    Question(
        "q06", "Your best friend confesses they have been robbing the temple "
               "-- to pay for their mother's medicine.",
        (
            Option("q06_a", "You turn them in. The law does not have a 'good "
                            "reason' clause.", 0.75, 0.0),
            Option("q06_b", "You help them -- and start a fund to repay the "
                            "temple.", -0.5, 0.75),
            Option("q06_c", "You tell the temple's abbot, who is known to be "
                            "merciful.", 0.5, 0.25),
            Option("q06_d", "You never heard it.", 0.0, -0.25),
        ),
    ),
    Question(
        "q07", "Your rival -- who has humiliated you three times -- lies "
               "injured and alone on the trail.",
        (
            Option("q07_a", "You help them up. This is not the story you want "
                            "to be in.", 0.0, 0.75),
            Option("q07_b", "You take their purse and leave them to the crows.",
                   -0.75, -0.75),
            Option("q07_c", "You save them -- then hold it over their head "
                            "forever.", 0.25, -0.25),
            Option("q07_d", "You stand guard until they can walk. A debt paid "
                            "is a debt paid.", 0.75, 0.5),
        ),
    ),
    Question(
        "q08", "The town's new law forbids singing in the square. The penalty "
               "is a week in the stocks. Everyone hates it, but it is law.",
        (
            Option("q08_a", "You sing. Loudly. In the square.", -0.75, 0.25),
            Option("q08_b", "You petition the council to repeal it -- through "
                            "channels.", 0.75, 0.25),
            Option("q08_c", "You obey. Bad laws are still laws until they "
                            "change.", 0.75, -0.25),
            Option("q08_d", "You start an underground choir in a basement.",
                   -0.5, 0.75),
            Option("q08_e", "You ignore it. You never liked the square anyway.",
                   -0.25, 0.0),
        ),
    ),
    Question(
        "q09", "A burly thug is shaking down a kid for 'protection' money.",
        (
            Option("q09_a", "You walk over and stand between them.", 0.25, 0.75),
            Option("q09_b", "You alert the watch. This is their job.", 0.75, 0.25),
            Option("q09_c", "You wait until the thug is alone and return the "
                            "favor -- with interest.", -0.75, 0.25),
            Option("q09_d", "Not your business. The kid will learn.", -0.25, -0.5),
            Option("q09_e", "You offer the thug a real job, so they can stop "
                            "shaking kids down.", 0.5, 0.5),
        ),
    ),
    Question(
        "q10", "A merchant entrusts you with a chest of gold to deliver. Your "
               "party is broke and hungry.",
        (
            Option("q10_a", "You deliver every coin. Their trust is the "
                            "treasure.", 0.75, 0.75),
            Option("q10_b", "You borrow a handful. You will replace it before "
                            "they notice.", -0.25, -0.25),
            Option("q10_c", "You take it all and start a new life elsewhere.",
                   -0.75, -0.75),
            Option("q10_d", "You deliver it -- and charge them a modest "
                            "'delivery fee'.", 0.5, -0.25),
        ),
    ),
    Question(
        "q11", "Your keep is surrounded. The enemy offers mercy if you "
               "surrender; your scouts say you can hold three days.",
        (
            Option("q11_a", "You surrender. Three days of corpses is not a "
                            "victory.", 0.0, 0.5),
            Option("q11_b", "You fight to the last. Honor is not negotiable.",
                   0.75, -0.25),
            Option("q11_c", "You slip everyone out through the sewers at "
                            "night.", -0.75, 0.25),
            Option("q11_d", "You surrender, then poison their wine at the "
                            "victory feast.", -0.5, -0.75),
        ),
    ),
    Question(
        "q12", "A starving family shares your campfire. You have one day's "
               "rations.",
        (
            Option("q12_a", "You cook everything and eat together.", -0.25, 0.75),
            Option("q12_b", "You share half. You have a quest to finish.",
                   0.25, 0.25),
            Option("q12_c", "You eat quickly and leave before dawn.", -0.25, -0.5),
            Option("q12_d", "You trade the rations for a promise they will "
                            "help you later.", 0.5, -0.25),
        ),
    ),
    Question(
        "q13", "The trial for the champion's belt: the examiner steps out, "
               "leaving the answer scroll on the desk.",
        (
            Option("q13_a", "You read it. Winning is winning.", -0.75, -0.25),
            Option("q13_b", "You memorize it, then win anyway. Rules are for "
                            "people who cannot read.", 0.5, -0.5),
            Option("q13_c", "You fetch the examiner and hand them the scroll.",
                   0.75, 0.5),
            Option("q13_d", "You announce the leak to the whole hall and "
                            "demand a re-trial for everyone.", -0.5, 0.75),
        ),
    ),
    Question(
        "q14", "You are alone in an ancient, pristine forest, and your apple "
               "core is done.",
        (
            Option("q14_a", "You bury it. No one will know.", -0.5, 0.0),
            Option("q14_b", "You carry it out. The forest did not ask for your "
                            "trash.", 0.25, 0.5),
            Option("q14_c", "You drop it. An apple core is an apple core.",
                   -0.25, -0.25),
            Option("q14_d", "You plant the seeds before you go.", 0.0, 0.75),
        ),
    ),
    Question(
        "q15", "You have won the duel. Your enemy kneels, sword dropped, "
               "begging for mercy.",
        (
            Option("q15_a", "You spare them. Killing a beaten foe is for "
                            "cowards.", 0.0, 0.75),
            Option("q15_b", "You take their oath of fealty instead.", 0.75, 0.25),
            Option("q15_c", "You kill them. They would do the same to you.",
                   -0.75, -0.5),
            Option("q15_d", "You spare them -- for a price they will pay for "
                            "years.", 0.5, -0.5),
        ),
    ),
    Question(
        "q16", "A runaway cart barrels toward five tied captives. A lever "
               "would divert it onto one. The lever is right there.",
        (
            Option("q16_a", "You pull it. One is less than five; the math is "
                            "the mercy.", 0.5, 0.25),
            Option("q16_b", "You do not. You are not the one who tied them up.",
                   -0.25, 0.0),
            Option("q16_c", "You cut the rope you can reach and shout the rest "
                            "to run.", -0.75, 0.5),
            Option("q16_d", "You hold the lever and make the town pay you to "
                            "pull it.", 0.5, -0.75),
        ),
    ),
    Question(
        "q17", "A friend's new spouse asks if you like their terrible soup. "
               "You have known the friend since childhood.",
        (
            Option("q17_a", "You eat two bowls and lie warmly.", -0.25, 0.5),
            Option("q17_b", "You tell them it needs salt -- gently, kindly.",
                   0.25, 0.25),
            Option("q17_c", "You say exactly what you think. Truth is the only "
                            "kindness.", -0.5, -0.25),
            Option("q17_d", "You loudly change the subject to the weather.",
                   0.0, 0.0),
        ),
    ),
    Question(
        "q18", "The realm's ruler is corrupt. You hold the army's loyalty. "
               "The council whispers 'usurp'.",
        (
            Option("q18_a", "You take the throne. The realm comes first.",
                   -0.25, 0.25),
            Option("q18_b", "You call for a lawful vote of no confidence.",
                   0.75, 0.5),
            Option("q18_c", "You publish their crimes and let the people "
                            "decide.", -0.75, 0.5),
            Option("q18_d", "You do nothing. Thrones are poison.", 0.0, -0.25),
        ),
    ),
)


# ── scoring ────────────────────────────────────────────────────────────────


def _bucket(score: float, positive: str, negative: str) -> str:
    if score > NEUTRAL_BAND:
        return positive
    if score < -NEUTRAL_BAND:
        return negative
    return "neutral"


def _resolve(order_bucket: str, moral_bucket: str) -> str:
    if order_bucket == "neutral" and moral_bucket == "neutral":
        return "true_neutral"
    return f"{order_bucket}_{moral_bucket}"


def score_answers(answers: Mapping[str, str]) -> AlignmentResult:
    """Fold answers into one alignment. Pure and deterministic.

    Raises ValueError on anything that is not a complete answer set: a missing
    question, an option id that belongs to another question, an extra key, a
    non-question key -- the same refusal discipline as `challenge.check_answers`.
    """
    qids = {q.id for q in QUESTIONS}
    if not answers:
        raise ValueError("no answers were given -- there is nothing to score")
    extra = [k for k in answers if k not in qids]
    if extra:
        raise ValueError(f"answers include questions that were not asked: {sorted(extra)}")
    missing = [qid for qid in qids if qid not in answers]
    if missing:
        raise ValueError(f"missing answers for: {sorted(missing)}")

    law = 0.0
    good = 0.0
    for q in QUESTIONS:
        pick = answers[q.id]
        option = next((o for o in q.options if o.id == pick), None)
        if option is None:
            raise ValueError(
                f"{pick!r} is not an option of {q.id} -- an answer for another "
                "question is not an answer for this one"
            )
        law += option.law
        good += option.good

    n = len(QUESTIONS)
    law /= n
    good /= n
    order_bucket = _bucket(law, "lawful", "chaotic")
    moral_bucket = _bucket(good, "good", "evil")
    return AlignmentResult(
        order_score=round(law, 6),
        moral_score=round(good, 6),
        order_bucket=order_bucket,
        moral_bucket=moral_bucket,
        alignment=_resolve(order_bucket, moral_bucket),
    )


def questions_public() -> list[dict[str, Any]]:
    """The questions exactly as a caller may see them. No weights -- see the
    module docstring: the protocol does not hand out the answer key."""
    return [q.public() for q in QUESTIONS]


# ── the binding ────────────────────────────────────────────────────────────


def result_context(result: AlignmentResult) -> str:
    """The attestation binding: the exact result, spelled so a relabel cannot
    survive. Two tokens with the same alignment but different axis scores
    have different contexts; a verifier names one context, never 'any'."""
    return (
        f"alignment:{result.alignment}:law={result.order_score:+.3f}:"
        f"good={result.moral_score:+.3f}:quiz={QUIZ_VERSION}"
    )


def parse_result_context(ctx: str) -> dict[str, Any]:
    """Read a result context back for display. Raises ValueError on anything
    this module did not build -- verification never depends on this parser
    (the attestation verifies by EXACT string), it only makes a token human-
    readable."""
    if not (ctx or "").startswith("alignment:"):
        raise ValueError(f"{ctx!r} is not an alignment result context")
    rest = ctx[len("alignment:"):]
    # The alignment id is the first segment and carries no "="; everything
    # after it is key=value.
    segments = rest.split(":")
    alignment_id = segments[0]
    parts = dict(p.split("=", 1) for p in segments[1:] if "=" in p)
    if alignment_id not in ALIGNMENTS:
        raise ValueError(f"{ctx!r} names an unknown alignment {alignment_id!r}")
    if "quiz" not in parts:
        raise ValueError(f"{ctx!r} is missing the quiz version")
    parts["alignment"] = alignment_id
    return parts


def mint_badge(key: Key, *, sub: str, result: AlignmentResult,
               ttl_s: float = BADGE_TTL_S, now: Optional[float] = None) -> str:
    """Sign a badge claim: THIS identity got THIS result on THIS door.

    The verdict is HUMAN for the honest reason stated in the module docstring:
    the claim arrived from an authenticated identity on an interactive session.
    `score` stays None -- nothing here graded humanity on a 0-100 scale, and a
    number with no judge behind it would be the package's own fail-open.
    """
    return mint(
        key,
        sub=sub,
        aud=ALIGNMENT_AUDIENCE,
        verdict=Verdict.HUMAN,
        score=None,
        ttl_s=ttl_s,
        method="alignment_quiz",
        ctx=result_context(result),
        now=now,
    )


def _read_ctx(token: str) -> Optional[str]:
    """Read a token's context WITHOUT verifying it.

    This exists to CONSTRUCT the verification parameters, never to decide
    anything: attest.verify() refuses a bound token when the verifier does not
    name the same context, so the only way to verify a badge token at all is
    to learn what it claims to be bound to -- and then let the signature and
    the exact-match comparison do the deciding. An unverifiable or missing ctx
    returns None, and verification then fails the normal way."""
    try:
        payload = token.split(".")[1]
        pad = "=" * (-len(payload) % 4)
        body = json.loads(base64.urlsafe_b64decode(payload + pad))
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    return body.get("ctx")


def verify_badge(token: str, key: Key, *, subject: Optional[str] = None,
                 now: Optional[float] = None, seen=None) -> Attestation:
    """Check a badge token against THIS door. Returns the Attestation or raises
    AttestationError -- the same refusal discipline as attest.verify()."""
    ctx = _read_ctx(token)
    return verify(token, key, audience=ALIGNMENT_AUDIENCE, subject=subject,
                  context=ctx, now=now, seen=seen)


# ── the badge ──────────────────────────────────────────────────────────────


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _shade(hex_color: str, factor: float = 0.55) -> str:
    """Darken a #rrggbb color for the badge's gradient. Pure, so the badge is
    deterministic given a result."""
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return "#%02x%02x%02x" % (int(r * factor), int(g * factor), int(b * factor))


def _axis_bar(x: float, y: float, score: float, low: str, high: str,
              color: str) -> str:
    """One axis bar: a track, a dot at the score, and the two pole labels.
    Positive scores sit on the right, so LAW and GOOD are the right poles."""
    width = 236
    dot_x = 12 + (max(-1.0, min(1.0, score)) + 1) / 2 * (width - 24)
    return (
        f'<g transform="translate({x},{y})">'
        f'<text x="0" y="-4" font-size="8" fill="rgba(255,255,255,.55)" '
        f'letter-spacing=".12em">{_esc(low)}</text>'
        f'<text x="{width}" y="-4" font-size="8" text-anchor="end" '
        f'fill="rgba(255,255,255,.55)" letter-spacing=".12em">{_esc(high)}</text>'
        f'<rect x="12" y="-3" width="{width - 24}" height="6" rx="3" '
        f'fill="rgba(0,0,0,.25)"/>'
        f'<circle cx="{dot_x:.1f}" cy="0" r="5" fill="#fff" stroke="{color}" '
        f'stroke-width="2"/>'
        f'</g>'
    )


def badge_svg(result: AlignmentResult, *, subject: Optional[str] = None,
              issued_at: Optional[float] = None) -> str:
    """The compact wall badge: alignment color, name, flavor, both axis
    scores, and the door's signature line. Pure -- same result, same bytes."""
    d = ALIGNMENTS[result.alignment]
    t = time.time() if issued_at is None else issued_at
    date = time.strftime("%Y-%m-%d", time.gmtime(t))
    # The subject is escaped EXACTLY ONCE, at the write site below -- escaping
    # it here AND there would double-escape every angle bracket (the badge
    # would render the literal text "&lt;script&gt;" instead of "<script>").
    footer = (f"awnest · {ALIGNMENT_AUDIENCE}"
              + (f" · {subject}" if subject else "")
              + (f" · {date}" if issued_at is not None else ""))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="340" height="170" '
        f'viewBox="0 0 340 170" role="img" aria-label="{_esc(d.name)} badge">'
        f'<defs><linearGradient id="awnest-bg" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" stop-color="{d.color}"/>'
        f'<stop offset="1" stop-color="{_shade(d.color)}"/>'
        f'</linearGradient></defs>'
        f'<rect x="2" y="2" width="336" height="166" rx="18" '
        f'fill="url(#awnest-bg)" stroke="rgba(255,255,255,.35)" stroke-width="2"/>'
        f'<text x="36" y="66" font-size="42" text-anchor="middle">{d.emoji}</text>'
        f'<text x="76" y="42" font-size="20" font-weight="700" fill="#ffffff">'
        f'{_esc(d.name)}</text>'
        f'<text x="76" y="59" font-size="10.5" font-style="italic" '
        f'fill="rgba(255,255,255,.85)">{_esc(d.flavor)}</text>'
        f'{_axis_bar(76, 88, result.order_score, "CHAOS", "LAW", d.color)}'
        f'{_axis_bar(76, 118, result.moral_score, "EVIL", "GOOD", d.color)}'
        f'<text x="17" y="162" font-size="8.5" fill="rgba(255,255,255,.6)">'
        f'{_esc(footer)}</text>'
        f'</svg>'
    )


def chart_svg(result: AlignmentResult) -> str:
    """The classic 3x3 chart with the earned cell lit. Columns run
    Lawful | Neutral | Chaotic (the chart's convention), rows Good | Neutral
    | Evil top to bottom."""
    d = ALIGNMENTS[result.alignment]
    order_axis = {"lawful": 0, "neutral": 1, "chaotic": 2}[result.order_bucket]
    moral_axis = {"good": 0, "neutral": 1, "evil": 2}[result.moral_bucket]
    cell = 116
    gap = 10
    pad = 46
    total = pad * 2 + cell * 3 + gap * 2
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" '
             f'height="{total}" viewBox="0 0 {total} {total}" '
             f'role="img" aria-label="{_esc(d.name)} alignment chart">']
    for col, label in enumerate(("LAWFUL", "NEUTRAL", "CHAOTIC")):
        parts.append(
            f'<text x="{pad + col * (cell + gap) + cell / 2}" y="22" '
            f'font-size="11" text-anchor="middle" fill="rgba(255,255,255,.7)" '
            f'letter-spacing=".18em">{label}</text>'
        )
    for row, label in enumerate(("GOOD", "NEUTRAL", "EVIL")):
        parts.append(
            f'<text x="14" y="{pad + row * (cell + gap) + cell / 2 + 4}" '
            f'font-size="11" fill="rgba(255,255,255,.7)" letter-spacing=".12em">'
            f'{label}</text>'
        )
    for row, moral in enumerate(("good", "neutral", "evil")):
        for col, order in enumerate(("lawful", "neutral", "chaotic")):
            align_id = _resolve(order, moral)
            ad = ALIGNMENTS[align_id]
            lit = row == moral_axis and col == order_axis
            x = pad + col * (cell + gap)
            y = pad + row * (cell + gap)
            fill = ad.color if lit else "#1c1c26"
            stroke = "rgba(255,255,255,.9)" if lit else "rgba(255,255,255,.14)"
            sw = 2.5 if lit else 1
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" rx="12" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
            )
            parts.append(
                f'<text x="{x + cell / 2}" y="{y + cell / 2 - 6}" font-size="30" '
                f'text-anchor="middle" opacity="{"1" if lit else ".35"}">'
                f'{ad.emoji}</text>'
            )
            parts.append(
                f'<text x="{x + cell / 2}" y="{y + cell / 2 + 22}" font-size="12.5" '
                f'font-weight="{"700" if lit else "400"}" text-anchor="middle" '
                f'fill="#ffffff" opacity="{"1" if lit else ".55"}">{_esc(ad.name)}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)
