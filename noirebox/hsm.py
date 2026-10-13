"""HSM signing — the same signer interface, hardware custody.

ADR 020's ladder, one rung below the keyholder: the key material lives in
a PKCS#11 token. `P11Signer` duck-types `.sign()` + `.public_hex()` like
`KeyPair` and `SocketSigner`, so every writer path accepts it unchanged —
and the keyholder daemon becomes the hardware bridge
(`noirebox keyholder --pkcs11-module ...`): the agent keeps speaking to
the socket, the socket keeps speaking to the token.

**What this closes — and what it does not.** The HSM does NOT change WHO
can ask for a signature: that remains the keyholder's socket premise.
It changes what a compromise COSTS. With a PEM, one read of the file is
permanent forgery capability — offline, forever. A non-extractable key
cannot be copied: forgery requires CONTINUOUS reachability to the token,
which is detectable, revocable, and rotatable. Blast radius: from
"key stolen" to "live abuse only".

**The honesty about SoftHSM2** (the CI token): SoftHSM2 is an HSM-shaped
FILE — it proves the INTERFACE (the PKCS#11 contract, determinism, key
continuity, drop-in composition), never the non-extractability. Real
hardware claims that; software tokens simulate it. And PKCS#11's own
`CKA_NEVER_EXTRACTABLE` is a label: an IMPORTED key reports False — the
token telling the truth, the seed did exist outside once. Only generation
on real silicon makes the label true. The attribute is a claim; the
hardware is the predicate — the same ladder, one rung further down.

Requires the optional dependency: `pip install noirebox[hsm]`
(python-pkcs11 0.7.0 — the 0.10 refactor does not wire signing).
Tested against SoftHSM2 2.6+/2.7; any PKCS#11 module speaking Ed25519
(CKM_EDDSA) should behave identically.
"""
from __future__ import annotations

import os

# DER OID 1.3.101.112 (Ed25519), as PKCS#11 CKA_EC_PARAMS expects it.
EC_PARAMS_ED25519 = bytes.fromhex("06032b6570")

_SOFTHSM_PATHS = (
    "/usr/lib/softhsm/libsofthsm2.so",            # Debian/Ubuntu
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",   # macOS (Homebrew arm64)
    "/usr/local/lib/softhsm/libsofthsm2.so",      # macOS (Intel)
)


def find_softhsm() -> str | None:
    """First SoftHSM2 module that exists on this machine — CI and docs use
    this to locate the software token. A real HSM passes its own module
    path instead."""
    env = os.environ.get("NOIREBOX_PKCS11_MODULE")
    if env and os.path.exists(env):
        return env
    for path in _SOFTHSM_PATHS:
        if os.path.exists(path):
            return path
    return None


def _der_octet_string(raw: bytes) -> bytes:
    """An OCTET STRING wrapper — what CKA_EC_POINT expects for a raw
    Edwards point."""
    return b"\x04" + bytes([len(raw)]) + raw


def _strip_der_octet_string(point: bytes) -> bytes:
    """Some tokens return the point wrapped, some raw — accept both."""
    if len(point) > 2 and point[0] == 0x04 and point[1] == len(point) - 2:
        return point[2:]
    return point


# One PKCS#11 session per (module, token) per process — SoftHSM2 treats
# login as token-global and refuses a second C_Login with
# UserAlreadyLoggedIn; real HSMs differ. The cache mirrors how production
# talks to a token: log in once, share the session.
_SESSIONS: dict[tuple[str, str], object] = {}


def _open_session(module: str, token_label: str, pin: str):
    import pkcs11

    key = (module, token_label)
    if key not in _SESSIONS:
        token = pkcs11.lib(module).get_token(token_label=token_label)
        try:
            _SESSIONS[key] = token.open(user_pin=pin, rw=True)
        except pkcs11.exceptions.UserAlreadyLoggedIn:
            # this process is already logged in to the token (SoftHSM2's
            # global login): a plain session sees the private objects
            _SESSIONS[key] = token.open(rw=True)
    return _SESSIONS[key]


class P11Signer:
    """A PKCS#11 token key as a drop-in signer: `.sign()` + `.public_hex()`.

    The session stays open for the signer's lifetime (the keyholder daemon
    serves sequentially, which is also what PKCS#11 sessions like). The
    private key is addressed by LABEL and never leaves the token: this
    class reads a public point and receives signatures, nothing else."""

    def __init__(self, module: str, *, token_label: str, pin: str,
                 key_label: str):
        try:
            import pkcs11
            from pkcs11 import Mechanism
        except ImportError as exc:  # pragma: no cover - guarded by extra
            raise ImportError(
                "P11Signer needs the PKCS#11 binding: "
                "pip install 'noirebox[hsm]'") from exc
        self._Mechanism = Mechanism
        self.module = module
        self.token_label = token_label
        self.key_label = key_label
        self._session = _open_session(module, token_label, pin)
        found = list(self._session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.constants.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.LABEL: key_label,
        }))
        if not found:
            self._session.close()
            raise KeyError(
                f"no private key labeled {key_label!r} in token "
                f"{token_label!r} — ensure it first (ensure_hsm_key)")
        self._priv = found[0]
        self._public_hex: str | None = None

    def sign(self, data: bytes) -> str:
        """Signs bytes ON THE TOKEN — Ed25519 is deterministic, so the
        signature is byte-identical to the same key material in a PEM."""
        sig = self._priv.sign(data, mechanism=self._Mechanism.EDDSA)
        return sig.hex()

    def public_hex(self) -> str:
        """The public half, read FROM THE TOKEN — the pin value learned
        from the device, not from any journal it sealed."""
        if self._public_hex is None:
            import pkcs11
            pubs = list(self._session.get_objects({
                pkcs11.Attribute.CLASS:
                    pkcs11.constants.ObjectClass.PUBLIC_KEY,
                pkcs11.Attribute.LABEL: self.key_label,
            }))
            if not pubs:
                raise KeyError(
                    f"no PUBLIC half labeled {self.key_label!r} in the "
                    "token — ensure_hsm_key creates both halves")
            self._public_hex = _strip_der_octet_string(
                pubs[0][pkcs11.Attribute.EC_POINT]).hex()
        return self._public_hex

    def close(self) -> None:
        self._session.close()


def ensure_hsm_key(module: str, *, token_label: str, pin: str,
                   key_label: str, pem: bytes | None = None) -> P11Signer:
    """The key exists on the token, or is put there — idempotent.

    With `pem` (an existing journal key), the SAME key is imported: the
    public hex does not move, no signature breaks, no rotation happens —
    the journal's continuity is the point. Without `pem`, a fresh seed is
    generated (an Ed25519 seed IS 32 uniform bytes; generation and import
    are the same code path on purpose — one path, one review).

    The honest labels: an imported key carries SENSITIVE (the token
    shields CKA_VALUE) but reports NEVER_EXTRACTABLE False — it did exist
    outside once. Only keys BORN on real hardware make that label true;
    on SoftHSM2 nothing here is hardware, and the docs say so."""
    import pkcs11
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)

    if pem is not None:
        priv = pkcs11_load_pem_or_none(pem)
        seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                  NoEncryption())
        pubraw = priv.public_key().public_bytes(Encoding.Raw,
                                                PublicFormat.Raw)
    else:
        seed = os.urandom(32)
        pubraw = Ed25519PrivateKey.from_private_bytes(seed).public_key() \
            .public_bytes(Encoding.Raw, PublicFormat.Raw)

    session = _open_session(module, token_label, pin)
    if True:
        existing = list(session.get_objects({
            pkcs11.Attribute.CLASS:
                pkcs11.constants.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.LABEL: key_label,
        }))
        if existing:
            return P11Signer(module, token_label=token_label, pin=pin,
                             key_label=key_label)  # idempotent: already there
        session.create_object({
            pkcs11.Attribute.CLASS:
                pkcs11.constants.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS,
            pkcs11.Attribute.EC_PARAMS: EC_PARAMS_ED25519,
            pkcs11.Attribute.VALUE: seed,
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.SIGN: True,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.EXTRACTABLE: False,
            pkcs11.Attribute.LABEL: key_label,
        })
        session.create_object({
            pkcs11.Attribute.CLASS:
                pkcs11.constants.ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS,
            pkcs11.Attribute.EC_PARAMS: EC_PARAMS_ED25519,
            pkcs11.Attribute.EC_POINT: _der_octet_string(pubraw),
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.VERIFY: True,
            pkcs11.Attribute.LABEL: key_label,
        })
    return P11Signer(module, token_label=token_label, pin=pin,
                     key_label=key_label)


def pkcs11_load_pem_or_none(pem: bytes):
    """PEM bytes → the Ed25519 private key object (seed extraction)."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key)
    priv = load_pem_private_key(pem, password=None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("the PEM does not contain an Ed25519 key — the "
                         "HSM import is continuity, not rotation")
    return priv
