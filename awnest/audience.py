"""Naming a door, so four different systems name it the same way.

An audience is just a string, and that is exactly the problem. The verifier and
the issuer have to spell it identically, they usually live in different repos, and
the two failure modes are not symmetric:

    the VERIFIER's spelling drifts   -> everyone is refused. Loud. Fixed in minutes.
    the ISSUER's spelling drifts     -> tokens are minted for a door nobody guards,
                                        and the door they were meant for goes on
                                        admitting whoever else can reach it. Silent.

So the shapes live here, built rather than typed, and the same helper is used by
whatever is doing the gating: a chat channel, a repository, a mesh, a tunnelled
service. Nothing here is clever. It exists so the four callers cannot disagree.

    audience("channel", "#playground")   -> "channel:#playground"
    audience("repo", "acme/widgets")     -> "repo:acme/widgets"

WILDCARDS ARE REFUSED
=====================
`*`, `any`, and the empty name are rejected rather than supported. A wildcard
audience is a skeleton key with a friendly name, and it always arrives as a
convenience during an incident -- which is the moment nobody is reading the diff.
"""
from __future__ import annotations

__all__ = ["KINDS", "audience", "parse", "SEPARATOR"]

SEPARATOR = ":"

#: The kinds in use. A closed set on purpose: a free-form kind is how "channel"
#: and "chan" end up guarding the same door with two names, which is the issuer
#: drift above.
KINDS = (
    "channel",   # a chat/relay channel -- who may POST here
    "repo",      # a repository -- whose commits are attested
    "mesh",      # a mesh/overlay -- who may JOIN
    "tunnel",    # a tunnelled service -- who may reach it from outside
    "app",       # a deployed application surface
    "action",    # one specific action: a purchase, a signup, a deletion
)

_REFUSED_NAMES = {"*", "any", "all", "-"}


def audience(kind: str, name: str) -> str:
    """Build an audience string. Raises ValueError rather than producing a wrong one."""
    k = (kind or "").strip().lower()
    if k not in KINDS:
        raise ValueError(f"unknown audience kind {kind!r}; expected one of {KINDS}")
    n = (name or "").strip()
    if not n:
        raise ValueError("an audience needs a name -- the specific door, not the category")
    if n.lower() in _REFUSED_NAMES:
        raise ValueError(
            f"{name!r} is a wildcard audience, which is a skeleton key. Name the door."
        )
    if any(c.isspace() for c in n):
        raise ValueError(
            f"{name!r} contains whitespace; an audience travels in headers and trailers "
            "where a space silently truncates it"
        )
    return f"{k}{SEPARATOR}{n}"


def parse(value: str) -> tuple[str, str]:
    """Split an audience back into (kind, name). Raises on anything this did not build."""
    if SEPARATOR not in (value or ""):
        raise ValueError(f"{value!r} is not an audience built by this module")
    kind, _, name = value.partition(SEPARATOR)
    if kind not in KINDS or not name:
        raise ValueError(f"{value!r} is not a valid audience")
    return kind, name
