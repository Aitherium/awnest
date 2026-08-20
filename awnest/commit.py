"""Attesting a commit: who stood behind this change, and were they a person.

WHY THIS IS NOT THE SAME QUESTION AS SIGNING
============================================
A signed commit says a KEY was present. In a world where most commits are written
by agents holding the same keys as the humans who run them, that is no longer the
interesting fact -- the key proves the machine, not the person, and every agent in
a fleet passes it. The question a reviewer actually has is: was a person involved
in this, at what strength, and which person.

So this attaches a separate, small claim to the commit message:

    Awnest-Attestation: awn1.<payload>.<sig>

carrying the identity (the subject), the verdict, the score, and a binding to the
CONTENT so it cannot be moved onto a different change.

THE BINDING PROBLEM, AND WHY IT IS THE TREE
===========================================
The obvious binding is the commit sha, and it is impossible: the attestation lives
inside the commit message, so the sha covers the attestation. You cannot put a
hash of a thing inside the thing.

The tree hash is the honest alternative. It covers exactly the CONTENT -- every
file, every byte -- and not the message, the author line or the parent. So:

    an attestation survives  a reword, a rebase, a cherry-pick, an amend of the
                             message: same content, still attested. Correct.
    an attestation does NOT  cover the parent, so the same content applied on a
                             different base carries the same attestation.

That second one is a real limit and is stated rather than hidden: this claims
"a person stood behind this CONTENT", not "a person approved this content ON THIS
BRANCH". If you need the stronger claim, put the base in the audience -- the
audience is where branch-specific policy belongs, and `repo:acme/widgets@release`
is a different door from `repo:acme/widgets`.

WHAT A VERIFIER MUST DO, AND WHAT IT USUALLY FORGETS
====================================================
Read the trailer, verify the token, AND compare the token's context against the
tree hash of the commit in front of you. `verify_commit` does all three because
the middle step alone -- a signature that checks out -- is the one that looks like
enough. A valid attestation lifted from another commit verifies perfectly; only
the content comparison notices.
"""
from __future__ import annotations

import re
from typing import Optional

from awnest.attest import Attestation, AttestationError, Key, Seen, mint, verify
from awnest.audience import audience
from awnest.verdict import Verdict

__all__ = [
    "TRAILER", "tree_context", "repo_audience", "attest_commit", "trailer_line",
    "find_trailer", "verify_commit",
]

#: The git trailer key. Git's own trailer rules apply: `Key: value` on its own
#: line in the last paragraph of the message.
TRAILER = "Awnest-Attestation"

_TRAILER_RE = re.compile(rf"^{TRAILER}:\s*(\S+)\s*$", re.M)
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


def tree_context(tree_sha: str) -> str:
    """The binding an attestation carries for a commit: its content, not its sha."""
    s = (tree_sha or "").strip().lower()
    if not _SHA_RE.match(s):
        raise ValueError(
            f"{tree_sha!r} is not a git object id. Pass the TREE hash "
            "(`git rev-parse HEAD^{tree}`), not the commit sha -- see this module's "
            "docstring for why the commit sha cannot work."
        )
    return f"tree:{s}"


def repo_audience(repo: str, ref: Optional[str] = None) -> str:
    """`repo:acme/widgets`, or `repo:acme/widgets@release` for a branch-specific door."""
    return audience("repo", f"{repo}@{ref}" if ref else repo)


def attest_commit(key: Key, *, identity: str, tree_sha: str, repo: str,
                  verdict: Verdict = Verdict.HUMAN, score: Optional[int] = None,
                  ref: Optional[str] = None, ttl_s: float = 365 * 24 * 3600.0,
                  method: str = "unspecified", now: Optional[float] = None) -> str:
    """Mint the token that goes in the trailer.

    `identity` is whoever the identity system says this is -- a user id, not a
    display name and not an email typed by the committer. Git's author field is
    caller-supplied text; keying anything on it is the oldest fail-open in version
    control.

    The default lifetime is a YEAR, and that is deliberate rather than lazy: a
    commit attestation is read during archaeology, years later, and an expiry that
    outlives the interesting window would make every old commit unverifiable. The
    freshness that matters -- was the check recent when the commit was made -- is
    `iat` compared against the commit date, which a verifier can do at any point.
    """
    return mint(key, sub=identity, aud=repo_audience(repo, ref), verdict=verdict,
                score=score, ttl_s=ttl_s, method=method, ctx=tree_context(tree_sha),
                now=now)


def trailer_line(token: str) -> str:
    """The exact line to append to a commit message."""
    if not token or any(c.isspace() for c in token):
        raise ValueError("a token containing whitespace cannot survive a git trailer")
    return f"{TRAILER}: {token}"


def find_trailer(message: str) -> Optional[str]:
    """Pull the token out of a commit message, or None.

    Returns the LAST one. A message with two is either a rebase artefact or an
    attempt to have a lenient parser pick the wrong one, and the last trailer is
    the one git itself reports.
    """
    found = _TRAILER_RE.findall(message or "")
    return found[-1] if found else None


def verify_commit(message: str, key: Key, *, repo: str, tree_sha: str,
                  ref: Optional[str] = None, identity: Optional[str] = None,
                  now: Optional[float] = None, seen: Optional[Seen] = None) -> Attestation:
    """Read, verify, AND bind to the content in front of you. Raises on anything else.

    A commit with no trailer raises rather than returning None: "unattested" and
    "attested" are a policy decision the CALLER makes, and a None here is the shape
    that gets `if att:`-ed into "unattested commits are fine" by accident.
    """
    token = find_trailer(message)
    if token is None:
        raise AttestationError(f"commit message carries no {TRAILER} trailer")
    return verify(token, key, audience=repo_audience(repo, ref),
                  subject=identity, context=tree_context(tree_sha), now=now, seen=seen)
