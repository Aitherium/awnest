"""Attestations: a human check, written down so someone else can check it.

WHY AN ATTESTATION AT ALL
=========================
The check and the door are usually not the same process, and often not the same
company. Something judged a human once; something else, later, has to act on
that. The naive answer is "call the verifier" -- which makes every gated action
depend on the verifier being up, and turns a verification outage into a site
outage. The other naive answer is a boolean in a session, which is a fact with no
provenance: nobody can tell where it came from or when.

So: a small signed statement, verifiable offline, that says WHO was judged, by
WHOM, WHEN, and FOR WHICH DOOR.

THE ATTACK THIS FORMAT IS SHAPED BY -- REPLAY
=============================================
The human-check economy is not "bots solve the puzzle". It is "a human solves it
once, cheaply, and the result is reused". Anything that comes back from a check
is a bearer credential, and a bearer credential with no audience is a skeleton
key: solve on the free forum, spend on the payments page.

Three fields do the work, and dropping any one of them silently restores the
attack:

    sub    WHO it is about. Without it the token is transferable between people.
    aud    WHICH door it is for. Without it, one solve opens every door on the
           internet that trusts the same issuer.
    nonce  ONE use, if you keep a seen-set. Without it, one solve opens the same
           door forever, which is the version everybody actually gets bitten by.

`exp` is the fourth and the least interesting: it bounds the damage, it does not
prevent it.

ALG CONFUSION -- WHY THE TOKEN DOES NOT CHOOSE
==============================================
The token carries `alg`, and the VERIFIER also declares one, and they must match
or verification fails. That looks redundant and is not: a verifier that reads the
algorithm out of the token lets the attacker pick it, which is how `alg: none`
and HMAC/RSA confusion emptied a decade of JWT deployments. Here the key object
decides, the token merely says what it claims, and a disagreement is a refusal.

HMAC OR ED25519 -- A REAL CHOICE, NOT A DEFAULT
===============================================
HMAC (stdlib, no extra) means the verifier holds the same secret that mints, so
every verifier is also an issuer. That is fine INSIDE one trust domain and wrong
the moment a third party verifies. Ed25519 (`pip install awnest[ed25519]`) lets a
stranger verify without being able to mint. The default is HMAC because it needs
nothing installed; the docstring says this out loud because "we shipped the
symmetric one and never revisited it" is the ordinary way this goes wrong.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from awnest.verdict import Verdict

__all__ = [
    "Attestation", "AttestationError", "Key", "HmacKey", "Ed25519Key",
    "mint", "verify", "Seen", "MemorySeen", "FileSeen",
    "ATTESTATION_FIELDS", "TOKEN_PREFIX", "ed25519_available",
]

#: The token's opening segment. Versioned so a format change is a loud refusal in
#: an old verifier rather than a signature error it will misreport as tampering.
TOKEN_PREFIX = "awn1"

#: EXACTLY the payload fields, in order. A constant the self-test asserts against
#: rather than a dict literal in `mint`, because the failure mode of a missing
#: field here is not an error -- it is a token that verifies fine and no longer
#: says what it is for. `aud` silently absent is a skeleton key.
#:
#: `ctx` is the optional fourth binding: what this attestation is ABOUT, beyond
#: who it is about and which door it opens -- a commit's tree, a request body's
#: hash, a room, a transfer. Its rule is symmetric and deliberately unforgiving: a
#: token carrying a context is REFUSED by any verifier that does not name the same
#: one, and a verifier that names a context refuses a token that carries none. A
#: binding that a caller can decline to check is not a binding, and forgetting to
#: check is what actually happens.
ATTESTATION_FIELDS = ("v", "alg", "sub", "aud", "ctx", "verdict", "score", "iat",
                      "exp", "nonce", "method")


class AttestationError(RuntimeError):
    """This attestation does not hold.

    Raised, never returned as a falsy Attestation or a None the caller might
    forget to check. The whole point of the module is that "could not verify"
    must be impossible to mistake for "verified".
    """


@dataclass(frozen=True)
class Attestation:
    """A verified statement. Only ever constructed by `verify` or `mint`."""

    sub: str
    aud: str
    verdict: Verdict
    score: Optional[int]
    iat: float
    exp: float
    nonce: str
    method: str
    ctx: Optional[str] = None
    alg: str = "hs256"
    v: int = 1

    def age_s(self, now: Optional[float] = None) -> float:
        return (time.time() if now is None else now) - self.iat


# --- keys ------------------------------------------------------------------


class Key(Protocol):
    """Something that can sign, verify, or both. `alg` is authoritative."""

    alg: str

    def sign(self, msg: bytes) -> bytes: ...

    def check(self, msg: bytes, sig: bytes) -> bool: ...


class HmacKey:
    """Shared-secret signing. Verifier == potential issuer; see the module docstring."""

    alg = "hs256"

    def __init__(self, secret: bytes | str) -> None:
        raw = secret.encode("utf-8") if isinstance(secret, str) else secret
        if len(raw) < 16:
            raise ValueError(
                "an attestation secret under 16 bytes is guessable, and a guessable "
                "signing key makes every rule in this module decorative"
            )
        self._secret = raw

    def sign(self, msg: bytes) -> bytes:
        return hmac.new(self._secret, msg, hashlib.sha256).digest()

    def check(self, msg: bytes, sig: bytes) -> bool:
        # compare_digest, not ==: a timing-variable comparison on a signature is a
        # forgery oracle, and it is one character to get wrong.
        return hmac.compare_digest(self.sign(msg), sig)


def ed25519_available() -> bool:
    """Is the optional asymmetric backend installed?

    A function rather than a module-level flag: the answer is used in an error
    message, and an error message that says "install the extra" when the extra is
    already installed sends people the wrong way.
    """
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
        return True
    except Exception:
        return False


class Ed25519Key:
    """Asymmetric signing: a stranger can verify without being able to mint.

    Constructed from raw 32-byte seeds/public keys so a caller never has to hand
    this module a PEM it might get wrong, and so a verify-only deployment can hold
    exactly the public half and nothing else.
    """

    alg = "ed25519"

    def __init__(self, *, private: Optional[bytes] = None, public: Optional[bytes] = None) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except Exception as exc:  # pragma: no cover - exercised only without the extra
            raise AttestationError(
                "ed25519 attestations need the optional dependency: pip install awnest[ed25519]"
            ) from exc
        if private is None and public is None:
            raise ValueError("Ed25519Key needs a private seed, a public key, or both")
        self._priv = Ed25519PrivateKey.from_private_bytes(private) if private else None
        if public is not None:
            self._pub = Ed25519PublicKey.from_public_bytes(public)
        else:
            assert self._priv is not None
            self._pub = self._priv.public_key()

    def sign(self, msg: bytes) -> bytes:
        if self._priv is None:
            raise AttestationError(
                "this key holds only the public half -- it can verify, not mint. That is "
                "the point of using ed25519; do not 'fix' it by shipping the private seed."
            )
        return self._priv.sign(msg)

    def check(self, msg: bytes, sig: bytes) -> bool:
        try:
            self._pub.verify(sig, msg)
            return True
        except Exception:
            return False


# --- replay -----------------------------------------------------------------


class Seen(Protocol):
    """A one-use ledger for nonces. `mark` returns False if it was already there.

    `now` is passed IN rather than read from the wall clock, and that is not
    ergonomics -- it is the bug this signature already caught. A ledger that prunes
    by `time.time()` while the verifier judges against an injected `now` purges the
    entry it just wrote whenever the two clocks disagree, and then accepts the
    replay. The verifier's clock has to be the ledger's clock.
    """

    def mark(self, nonce: str, exp: float, now: float) -> bool: ...


class MemorySeen:
    """Process-local. Honest about what it is: one process, one lifetime.

    Two workers behind a load balancer do NOT share this, so a token replayed to
    the other worker is accepted. That is stated here rather than discovered,
    because an in-memory replay guard looks exactly like a working one in every
    single-process test anyone writes.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def mark(self, nonce: str, exp: float, now: Optional[float] = None) -> bool:
        t = time.time() if now is None else now
        for k, v in list(self._seen.items()):
            if v < t:
                del self._seen[k]
        if nonce in self._seen:
            return False
        self._seen[nonce] = exp
        return True


class FileSeen:
    """A directory of spent nonces -- shared between processes on one host.

    Uses O_CREAT|O_EXCL, so the check and the claim are ONE atomic operation. An
    exists-then-write version has a window in which two concurrent requests both
    see "not spent", and a replay guard with a race is a replay guard that fails
    exactly under the load an attacker creates.
    """

    def __init__(self, directory: str | Path, *, sweep_every: int = 256) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        #: Spent nonces are swept periodically rather than never. "Never" is the
        #: version that ships, because an unbounded directory is invisible for
        #: months and then is a full disk on the machine holding the door.
        self.sweep_every = max(1, sweep_every)
        self._marks = 0

    def _path(self, nonce: str) -> Path:
        # Hash, never the raw nonce: a nonce can be any string a peer chose, and
        # writing peer-chosen text into a filename is a path-traversal invitation.
        return self.dir / hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:32]

    def mark(self, nonce: str, exp: float, now: Optional[float] = None) -> bool:
        t = time.time() if now is None else now
        p = self._path(nonce)
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(str(exp))
        self._marks += 1
        if self._marks % self.sweep_every == 0:
            self.sweep(t)
        return True

    def sweep(self, now: Optional[float] = None) -> int:
        """Drop spent nonces that can no longer be replayed. Returns how many went.

        A file whose contents will not parse is KEPT, never deleted: an unreadable
        ledger entry is the one case where guessing frees a nonce for reuse, and a
        replay guard that fails open under corruption is not a replay guard.
        """
        t = time.time() if now is None else now
        gone = 0
        for f in self.dir.iterdir():
            try:
                if float(f.read_text(encoding="utf-8").strip()) < t:
                    f.unlink()
                    gone += 1
            except (OSError, ValueError):
                continue
        return gone


# --- the format -------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def payload_for(*, sub: str, aud: str, verdict: Verdict, score: Optional[int],
                iat: float, ttl_s: float, nonce: str, method: str, alg: str,
                ctx: Optional[str] = None) -> dict[str, Any]:
    """The signed body. Pure, so the field set is testable with no key and no clock."""
    if not sub:
        raise ValueError("an attestation with no subject is transferable between people")
    if not aud:
        raise ValueError(
            "an attestation with no audience opens every door that trusts this issuer -- "
            "name the one door it is for"
        )
    if ttl_s <= 0:
        raise ValueError("ttl_s must be positive")
    if verdict is Verdict.UNKNOWN:
        raise ValueError(
            "refusing to mint an attestation for UNKNOWN. A signed 'we could not tell' is "
            "read downstream as a signed 'we checked' -- that is the fail-open this "
            "package exists to prevent."
        )
    if ctx is not None and not str(ctx).strip():
        raise ValueError(
            "ctx must be a real binding or absent -- an empty string is a binding that "
            "matches nothing and refuses everyone, which reads as a broken door"
        )
    return {
        "v": 1,
        "alg": alg,
        "sub": sub,
        "aud": aud,
        "ctx": ctx,
        "verdict": verdict.value,
        "score": score,
        "iat": iat,
        "exp": iat + ttl_s,
        "nonce": nonce,
        "method": method,
    }


def mint(key: Key, *, sub: str, aud: str, verdict: Verdict, score: Optional[int] = None,
         ttl_s: float = 3600.0, method: str = "unspecified", ctx: Optional[str] = None,
         now: Optional[float] = None, nonce: Optional[str] = None) -> str:
    """Sign a statement. Returns the token; raises ValueError on an unmintable one."""
    iat = time.time() if now is None else now
    body = payload_for(sub=sub, aud=aud, verdict=verdict, score=score, iat=iat,
                       ttl_s=ttl_s, nonce=nonce or secrets.token_urlsafe(16),
                       method=method, alg=key.alg, ctx=ctx)
    # sort_keys + separators so the bytes signed are reproducible across
    # interpreters. A canonical form is not cosmetic here: re-serialising a parsed
    # payload has to produce the same bytes or verification is version-dependent.
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed = f"{TOKEN_PREFIX}.{_b64(raw)}"
    return f"{signed}.{_b64(key.sign(signed.encode('ascii')))}"


def verify(token: str, key: Key, *, audience: str, subject: Optional[str] = None,
           context: Optional[str] = None, now: Optional[float] = None,
           seen: Optional[Seen] = None) -> Attestation:
    """Check a token against THIS door. Returns the Attestation or raises.

    `audience` is required and positional-by-keyword on purpose: the one call a
    caller would omit is the one that turns this into a skeleton key, and an
    optional argument is an argument somebody omits.
    """
    if not audience:
        raise ValueError("verify() needs the audience of the door being opened")
    parts = (token or "").split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise AttestationError("not an awnest attestation (or a different format version)")
    try:
        body = json.loads(_unb64(parts[1]))
        sig = _unb64(parts[2])
    except Exception as exc:
        raise AttestationError(f"attestation is not decodable: {exc}") from exc
    if not isinstance(body, dict):
        raise AttestationError("attestation payload is not an object")

    missing = [f for f in ATTESTATION_FIELDS if f not in body]
    if missing:
        # Refuse rather than default. A missing `aud` defaulted to "any" is the
        # whole attack, and a missing `verdict` defaulted to human is worse.
        raise AttestationError(f"attestation is missing required field(s): {missing}")

    # The KEY decides the algorithm; the token only claims one. See the module
    # docstring -- reading `alg` out of the token is how attackers pick it.
    if body["alg"] != key.alg:
        raise AttestationError(
            f"attestation claims alg={body['alg']!r} but this verifier holds a "
            f"{key.alg!r} key -- refusing rather than trusting the token's claim"
        )
    if not key.check(f"{parts[0]}.{parts[1]}".encode("ascii"), sig):
        raise AttestationError("signature does not verify")

    t = time.time() if now is None else now
    if body["aud"] != audience:
        raise AttestationError(
            f"attestation is for audience {body['aud']!r}, not {audience!r} -- one solve "
            "does not open every door"
        )
    if body.get("ctx") != context:
        # Symmetric on purpose -- see ATTESTATION_FIELDS. Either direction is a
        # caller using a token for something it was not bound to, and the direction
        # that would otherwise pass silently (a bound token at an unbound verifier)
        # is the one that matters: it is how a commit attestation gets spent on a
        # login, or a login attestation on a payment.
        raise AttestationError(
            f"attestation context is {body.get('ctx')!r}, not {context!r} -- a binding "
            "that either side can decline to check is not a binding"
        )
    if subject is not None and body["sub"] != subject:
        raise AttestationError(
            f"attestation is about {body['sub']!r}, not {subject!r} -- a human check is "
            "not transferable"
        )
    if float(body["exp"]) < t:
        raise AttestationError("attestation has expired")
    if float(body["iat"]) > t + 60:
        raise AttestationError("attestation is issued in the future -- refused, not accepted early")
    try:
        verdict = Verdict(body["verdict"])
    except ValueError as exc:
        raise AttestationError(f"unknown verdict {body['verdict']!r}") from exc
    if verdict is Verdict.UNKNOWN:
        raise AttestationError("attestation records UNKNOWN, which admits nobody")

    if seen is not None and not seen.mark(str(body["nonce"]), float(body["exp"]), t):
        raise AttestationError("attestation has already been spent (replay)")

    return Attestation(
        sub=body["sub"], aud=body["aud"], verdict=verdict, score=body["score"],
        iat=float(body["iat"]), exp=float(body["exp"]), nonce=str(body["nonce"]),
        method=str(body["method"]), ctx=body.get("ctx"), alg=str(body["alg"]),
        v=int(body["v"]),
    )
