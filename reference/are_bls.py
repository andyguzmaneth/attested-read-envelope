"""
BLS12-381 sync-committee signing for the ARE reference impl.

Real cryptography: py_ecc G2ProofOfPossession (ciphersuite
BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_), G1 pubkeys (48-byte compressed),
G2 signatures (96-byte compressed). FastAggregateVerify per consensus spec.

Key generation is SEEDED (see are_generate.py random.seed) so vectors are
byte-identical on every regeneration. BLS Sign is deterministic given the key,
so signatures are stable once the keys are stable.
"""

from py_ecc.bls import G2ProofOfPossession as bls


def sk_to_pk(sk: int) -> bytes:
    return bls.SkToPk(sk)


def sign(sk: int, message: bytes) -> bytes:
    return bls.Sign(sk, message)


def fast_aggregate_verify(pubkeys, message: bytes, signature: bytes) -> bool:
    try:
        return bls.FastAggregateVerify(pubkeys, message, signature)
    except Exception:
        return False


def aggregate(signatures):
    return bls.Aggregate(signatures)
