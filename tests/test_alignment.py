"""Tests for the awnest alignment door.

The CLI's `--self-test` proves determinism, full reachability of all nine
cells, strict refusals, and the result-binding of the badge attestation. This
file adds the boundary maths and the exact refusal cases a self-test would
have to bend its shape for: the neutral band edges, the context parser, the
SVG shapes, and the badge being rejected against a DIFFERENT result.
"""
from __future__ import annotations

import pytest
from awnest.alignment import (
    ALIGNMENT_AUDIENCE,
    ALIGNMENT_IDS,
    ALIGNMENTS,
    NEUTRAL_BAND,
    QUESTIONS,
    QUIZ_VERSION,
    _bucket,
    badge_svg,
    chart_svg,
    mint_badge,
    parse_result_context,
    questions_public,
    result_context,
    score_answers,
    verify_badge,
)
from awnest.attest import AttestationError, HmacKey, verify


def _answers(first_only: bool = False) -> dict[str, str]:
    """A complete answer set: every question's first option."""
    return {q.id: q.options[0].id for q in QUESTIONS}


# ── the bank ───────────────────────────────────────────────────────────────


def test_nine_cells_and_chart_naming() -> None:
    assert len(ALIGNMENT_IDS) == 9
    assert ALIGNMENT_IDS == (
        "lawful_good", "neutral_good", "chaotic_good", "lawful_neutral",
        "true_neutral", "chaotic_neutral", "lawful_evil", "neutral_evil",
        "chaotic_evil",
    )
    for aid in ALIGNMENT_IDS:
        d = ALIGNMENTS[aid]
        assert d.id == aid
        assert d.name and d.emoji and d.flavor
        assert d.color.startswith("#") and len(d.color) == 7


def test_questions_are_well_formed() -> None:
    seen: set[str] = set()
    for q in QUESTIONS:
        assert q.id not in seen, f"duplicate question id {q.id}"
        seen.add(q.id)
        assert len(q.options) >= 2, f"{q.id} needs more than one option"
        for o in q.options:
            assert o.id.startswith(q.id), f"{o.id} does not belong to {q.id}"
            assert -1.0 <= o.law <= 1.0 and -1.0 <= o.good <= 1.0
            assert isinstance(o.law, float) and isinstance(o.good, float)


def test_public_questions_never_carry_weights() -> None:
    for q in questions_public():
        for o in q["options"]:
            # The dict must be EXACTLY {id, text} -- key check, not a string
            # scan, because the prose legitimately says "law" and "good".
            assert set(o) == {"id", "text"}


# ── the neutral band ───────────────────────────────────────────────────────


def test_bucket_boundaries_are_inclusive() -> None:
    assert _bucket(NEUTRAL_BAND, "lawful", "chaotic") == "neutral"
    assert _bucket(-NEUTRAL_BAND, "lawful", "chaotic") == "neutral"
    assert _bucket(NEUTRAL_BAND + 0.001, "lawful", "chaotic") == "lawful"
    assert _bucket(-NEUTRAL_BAND - 0.001, "lawful", "chaotic") == "chaotic"
    assert _bucket(0.0, "good", "evil") == "neutral"


def test_scoring_is_deterministic_and_reaches_a_cell() -> None:
    a = score_answers(_answers())
    b = score_answers(_answers())
    assert a == b
    assert a.alignment in ALIGNMENT_IDS
    assert -1.0 <= a.order_score <= 1.0
    assert -1.0 <= a.moral_score <= 1.0


def test_true_neutral_resolver_maps_the_composite_id() -> None:
    # The alignment id is a composite of the two axis buckets, and the
    # neutral/neutral pair is the one cell whose id is NOT the two words
    # joined by an underscore. The CLI self-test PROVES a real answer set
    # lands there (bounded search over the weight space); here we pin the
    # resolver's spelling so the id in attestations stays stable.
    from awnest.alignment import AlignmentResult, _resolve

    assert _resolve("neutral", "neutral") == "true_neutral"
    r = AlignmentResult(0.0, 0.0, "neutral", "neutral", "true_neutral")
    assert r.alignment == "true_neutral"
    assert r.public()["name"] == "True Neutral"


# ── refusals ───────────────────────────────────────────────────────────────


def test_score_refuses_incomplete_or_crossed_sets() -> None:
    with pytest.raises(ValueError):
        score_answers({})
    partial = _answers()
    partial.pop(next(iter(partial)))
    with pytest.raises(ValueError):
        score_answers(partial)
    crossed = _answers()
    crossed["q01"] = "q02_a"
    with pytest.raises(ValueError):
        score_answers(crossed)
    unknown_question = _answers()
    unknown_question["q99"] = "q99_a"
    with pytest.raises(ValueError):
        score_answers(unknown_question)


def test_result_context_round_trip() -> None:
    r = score_answers(_answers())
    ctx = result_context(r)
    assert ctx.startswith("alignment:")
    assert f"quiz={QUIZ_VERSION}" in ctx
    parsed = parse_result_context(ctx)
    assert parsed["alignment"] == r.alignment
    assert "law=" in ctx and "good=" in ctx
    with pytest.raises(ValueError):
        parse_result_context("tree:abc123")


# ── the badge attestation ──────────────────────────────────────────────────


def test_badge_mint_verify_round_trip() -> None:
    key = HmacKey("a-test-secret-that-is-long-enough")
    r = score_answers(_answers())
    t = 1_700_000_000.0
    token = mint_badge(key, sub="u_42", result=r, now=t)
    att = verify_badge(token, key, subject="u_42", now=t + 10)
    assert att.sub == "u_42"
    assert att.aud == ALIGNMENT_AUDIENCE
    assert att.ctx == result_context(r)
    assert att.method == "alignment_quiz"


def test_badge_refuses_wrong_key_wrong_subject_wrong_door() -> None:
    key = HmacKey("a-test-secret-that-is-long-enough")
    r = score_answers(_answers())
    t = 1_700_000_000.0
    token = mint_badge(key, sub="u_42", result=r, now=t)
    with pytest.raises(AttestationError):
        verify_badge(token, HmacKey("another-secret-that-is-long"), now=t + 10)
    with pytest.raises(AttestationError):
        verify_badge(token, key, subject="u_43", now=t + 10)
    with pytest.raises(AttestationError):
        verify(token, key, audience="action:other-door", now=t + 10)


def test_badge_refuses_a_different_result() -> None:
    key = HmacKey("a-test-secret-that-is-long-enough")
    t = 1_700_000_000.0
    good = score_answers(_answers())
    evil = score_answers({q.id: q.options[-1].id for q in QUESTIONS})
    token = mint_badge(key, sub="u_42", result=good, now=t)
    # The attestation must not verify against the other result's context --
    # that is the relabel attack the binding exists to stop.
    with pytest.raises(AttestationError):
        verify(token, key, audience=ALIGNMENT_AUDIENCE,
               context=result_context(evil), now=t + 10)


def test_badge_requires_the_door_context() -> None:
    key = HmacKey("a-test-secret-that-is-long-enough")
    r = score_answers(_answers())
    token = mint_badge(key, sub="u_42", result=r,
                       now=1_700_000_000.0)
    # A verifier that names no context must refuse a bound token (the
    # symmetric rule in attest.py -- a binding either side can skip is none).
    with pytest.raises(AttestationError):
        verify(token, key, audience=ALIGNMENT_AUDIENCE, now=1_700_000_010.0)


# ── the SVG ────────────────────────────────────────────────────────────────


def test_badge_svg_renders_the_result() -> None:
    r = score_answers(_answers())
    svg = badge_svg(r, subject="u_42", issued_at=1_700_000_000.0)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert ALIGNMENTS[r.alignment].name in svg
    assert ALIGNMENTS[r.alignment].emoji in svg
    assert "action:alignment_badge" in svg
    assert "u_42" in svg
    assert "2023" in svg  # 2023-11-14 from the fixed epoch


def test_chart_svg_has_nine_cells_and_highlights() -> None:
    r = score_answers(_answers())
    chart = chart_svg(r)
    assert chart.startswith("<svg")
    assert chart.count("<rect") == 9
    # exactly one lit cell -- the earned one gets the white ring
    assert chart.count('stroke="rgba(255,255,255,.9)"') == 1


def test_svg_escapes_the_subject() -> None:
    r = score_answers(_answers())
    svg = badge_svg(r, subject='"><script>alert(1)</script>')
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
