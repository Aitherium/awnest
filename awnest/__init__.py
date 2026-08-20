"""awnest -- prove there is a human before you let them into the nest.

    from awnest import Nest, Evidence, Policy, HmacKey

    nest = Nest("checkout", key=HmacKey(secret), policy=Policy(min_score=70))
    nest.require(token=attestation, subject=user_id)   # raises NotAdmitted

Three planes, kept apart on purpose:

    verdict    what evidence adds up to, and the rule that no evidence is not a pass
    attest     a signed statement bound to one subject, one door, one use
    nest       the door itself

The parts that need the outside world -- a judge, a humanity-check service -- are
in `judge` and `client` and import httpx. The three above are stdlib only, so the
gate keeps working on a machine that cannot reach anything.
"""
from awnest.attest import (
    Attestation,
    AttestationError,
    Ed25519Key,
    FileSeen,
    HmacKey,
    MemorySeen,
    mint,
    verify,
)
from awnest.audience import KINDS, audience
from awnest.challenge import (
    CHALLENGES,
    Challenge,
    Judgement,
    check_answers,
    judge_prompt,
    parse_judgement,
    select,
)
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

__version__ = "0.1.0"

__all__ = [
    "Verdict", "Evidence", "Policy", "Assessment", "assess", "DECLARED_AGENT",
    "Attestation", "AttestationError", "HmacKey", "Ed25519Key", "mint", "verify",
    "MemorySeen", "FileSeen",
    "Challenge", "CHALLENGES", "select", "check_answers", "judge_prompt",
    "parse_judgement", "Judgement",
    "Nest", "NotAdmitted",
    "audience", "KINDS",
    "attest_commit", "verify_commit", "trailer_line", "find_trailer", "tree_context",
    "repo_audience", "TRAILER",
    "__version__",
]
