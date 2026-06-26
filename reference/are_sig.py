"""
provider_sig (spec §Verification step 10) signing/verification for the ARE
reference impl.

The spec declares two schemes via the `sig_alg` discriminant:
  1 = secp256k1 ECDSA
  2 = ed25519

This reference implements **ed25519** with REAL cryptography (pycryptodome
`Crypto.Signature.eddsa`, RFC 8032). The provider key is a raw 32-byte ed25519
public key; the signature is the raw 64-byte ed25519 signature over
`hash_tree_root(envelope_without_provider_sig)` (see are_verify.envelope_signing_root).

secp256k1 (sig_alg == 1) is part of the spec but is NOT implemented in this
reference (pycryptodome does not expose the secp256k1 curve, and we deliberately
add no new dependency). A verifier encountering sig_alg == 1 in this reference
reports it as unverifiable; the shipped provider_sig vectors use ed25519. This is
a coverage/honesty note, not a soundness gap — step 10's control flow (independent
key resolution + verify-or-reject) is exercised identically by the ed25519 path.
"""

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

import are_constants as C


def ed25519_keypair_from_seed(seed32: bytes):
    """Deterministic ed25519 keypair from a 32-byte seed (RFC 8032 secret seed).
    Returns (private_key_obj, public_key_raw_32). Deterministic so vectors are
    byte-reproducible."""
    assert len(seed32) == 32
    sk = ECC.construct(curve="ed25519", seed=seed32)
    pub_raw = sk.public_key().export_key(format="raw")
    return sk, pub_raw


def ed25519_sign(sk, message: bytes) -> bytes:
    signer = eddsa.new(sk, "rfc8032")
    return signer.sign(message)


def ed25519_verify(pub_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pub = ECC.import_key(pub_raw, curve_name="ed25519")
        verifier = eddsa.new(pub, "rfc8032")
        verifier.verify(message, signature)
        return True
    except Exception:
        return False


def verify_provider_sig(sig_alg: int, pub_key: bytes, message: bytes,
                        signature: bytes) -> bool:
    """Dispatch by sig_alg. Returns True iff the signature verifies under the
    independently-resolved key. Unknown / unimplemented schemes return False
    (rejected when relied upon)."""
    if sig_alg == C.SIG_ALG_ED25519:
        return ed25519_verify(pub_key, message, signature)
    if sig_alg == C.SIG_ALG_SECP256K1:
        # Declared by the spec but not implemented in this reference (no secp256k1
        # in pycryptodome; no new dependency added). Treat as unverifiable here.
        return False
    return False
