"""
EIP-1186 Merkle-Patricia proof primitives for the ARE reference impl (v0.5).

Real cryptography: Keccak-256 (Ethereum variant, via pycryptodome) over
RLP-encoded trie nodes.

v0.5 UPGRADE: this is now a REAL hexary Merkle-Patricia verifier — it walks
branch (17-item), extension (2-item, even/odd hex-prefix), and leaf (2-item)
nodes along the keccak256(key) nibble path, dereferencing child node hashes
against the proof set, exactly as EIP-1186 `accountProof` / `storageProof`
require. It verifies real mainnet `eth_getProof` responses (see
are_real_vectors.py). Inclusion returns the decoded terminal value; exclusion
verifies a genuine divergent/terminal path (not a truncated one).

The previous v0.4 single-account collapsed trie is removed; the MINIMAL-preset
vectors are regenerated through this same real hexary verifier (they just use a
small synthetic 2-account / 2-slot trie built node-by-node — see are_generate.py),
so there is no longer a "simplified single-account MPT" code path anywhere.
"""

from Crypto.Hash import keccak


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
# RLP encode/decode (sufficient for trie nodes + account/storage values)
# ---------------------------------------------------------------------------

def rlp_encode(item):
    if isinstance(item, bytes):
        return _rlp_encode_bytes(item)
    if isinstance(item, list):
        out = b"".join(rlp_encode(x) for x in item)
        return _rlp_encode_length(len(out), 0xC0) + out
    raise TypeError(f"cannot rlp-encode {type(item)}")


def _rlp_encode_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_encode_length(len(b), 0x80) + b


def _rlp_encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes


def rlp_decode(data: bytes):
    item, rest = _rlp_decode_item(data)
    assert rest == b"", "trailing bytes in RLP"
    return item


def _rlp_decode_item(data: bytes):
    if not data:
        raise ValueError("empty RLP")
    prefix = data[0]
    if prefix < 0x80:
        return data[0:1], data[1:]
    if prefix < 0xB8:
        ln = prefix - 0x80
        return data[1:1 + ln], data[1 + ln:]
    if prefix < 0xC0:
        ll = prefix - 0xB7
        ln = int.from_bytes(data[1:1 + ll], "big")
        start = 1 + ll
        return data[start:start + ln], data[start + ln:]
    if prefix < 0xF8:
        ln = prefix - 0xC0
        return _rlp_decode_list(data[1:1 + ln]), data[1 + ln:]
    ll = prefix - 0xF7
    ln = int.from_bytes(data[1:1 + ll], "big")
    start = 1 + ll
    return _rlp_decode_list(data[start:start + ln]), data[start + ln:]


def _rlp_decode_list(data: bytes):
    out = []
    while data:
        item, data = _rlp_decode_item(data)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# big-endian no-leading-zero helpers (ARE value canonical form)
# ---------------------------------------------------------------------------

def be_trim(x: int) -> bytes:
    if x == 0:
        return b""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def be_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


# ---------------------------------------------------------------------------
# Account RLP: [nonce, balance, storageRoot, codeHash]
# ---------------------------------------------------------------------------

EMPTY_STORAGE_ROOT = keccak256(rlp_encode(b""))
EMPTY_CODE_HASH = keccak256(b"")
# canonical empty MPT root (keccak256(rlp(""))) — geth EmptyRootHash sentinel
EMPTY_TRIE_ROOT = keccak256(rlp_encode(b""))


def encode_account(nonce: int, balance: int, storage_root: bytes, code_hash: bytes) -> bytes:
    return rlp_encode([be_trim(nonce), be_trim(balance), storage_root, code_hash])


def decode_account(rlp_bytes: bytes):
    nonce_b, balance_b, storage_root, code_hash = rlp_decode(rlp_bytes)
    return {
        "nonce": be_to_int(nonce_b),
        "balance": be_to_int(balance_b),
        "storageRoot": storage_root,
        "codeHash": code_hash,
    }


# ---------------------------------------------------------------------------
# Hexary MPT walk
# ---------------------------------------------------------------------------

def _nibbles(b: bytes):
    out = []
    for x in b:
        out.append(x >> 4)
        out.append(x & 0x0F)
    return out


def _decode_hp(encoded: bytes):
    """Decode a hex-prefix (compact) path. Returns (nibbles, is_leaf)."""
    nibs = _nibbles(encoded)
    flag = nibs[0]
    is_leaf = flag >= 2
    odd = flag & 1
    rest = nibs[1:] if odd else nibs[2:]
    return rest, is_leaf


class _Absent:
    pass


ABSENT = _Absent()


def _walk(key: bytes, proof_nodes, root: bytes):
    """Walk an EIP-1186 MPT proof for `key` against `root`.

    Returns the terminal value bytes if the key is INCLUDED, or ABSENT if the
    proof genuinely proves exclusion (terminal divergence / empty branch slot /
    diverging leaf or extension). Raises ValueError if the proof is malformed,
    truncated, or hash-inconsistent (these MUST be rejected, never treated as
    absence)."""
    nodes_by_hash = {keccak256(n): n for n in proof_nodes}
    path = _nibbles(key)
    idx = 0
    expected = root

    while True:
        # Empty trie sentinel
        if expected == EMPTY_TRIE_ROOT:
            return ABSENT
        node = nodes_by_hash.get(expected)
        if node is None:
            # Spec: a node may be inlined (<32 bytes) but mainnet account/storage
            # tries are deep enough that all proof nodes are referenced by hash.
            raise ValueError("proof node missing for hash (truncated proof)")
        decoded = rlp_decode(node)

        if isinstance(decoded, list) and len(decoded) == 17:
            # branch node
            if idx == len(path):
                # value is at branch[16]
                val = decoded[16]
                return val if len(val) > 0 else ABSENT
            nib = path[idx]
            child = decoded[nib]
            if len(child) == 0:
                return ABSENT  # empty slot -> proven absence
            idx += 1
            expected = _next_ref(child, nodes_by_hash)
            continue

        if isinstance(decoded, list) and len(decoded) == 2:
            enc_path, is_leaf = _decode_hp(decoded[0])
            remaining = path[idx:]
            if is_leaf:
                if remaining == enc_path:
                    return decoded[1]   # inclusion
                return ABSENT           # diverging leaf -> proven absence
            # extension node
            if remaining[:len(enc_path)] != enc_path:
                return ABSENT           # diverging extension -> proven absence
            idx += len(enc_path)
            expected = _next_ref(decoded[1], nodes_by_hash)
            continue

        raise ValueError("malformed MPT node")


def _next_ref(child, nodes_by_hash):
    """Resolve a child reference: either a 32-byte hash, or an inlined node
    (an RLP list <32 bytes). For inlined nodes we re-serialize and index by hash
    so the walk loop can fetch them uniformly."""
    if isinstance(child, bytes):
        if len(child) == 32:
            return child
        raise ValueError("unexpected short hash child")
    # inlined node (list): index it so the loop can resolve it
    enc = rlp_encode(child)
    h = keccak256(enc)
    nodes_by_hash[h] = enc
    return h


# ---------------------------------------------------------------------------
# Public API (account / storage inclusion + exclusion)
# ---------------------------------------------------------------------------

def verify_account_inclusion(address: bytes, account_proof, root: bytes):
    """Return decoded account dict, or None if absent / proof invalid."""
    try:
        val = _walk(keccak256(address), account_proof, root)
    except ValueError:
        return None
    if val is ABSENT:
        return None
    return decode_account(val)


def verify_account_exclusion(address: bytes, account_proof, root: bytes) -> bool:
    """True iff the proof genuinely proves `address` is absent from the state
    trie (a real terminal/divergent-path proof against `root`)."""
    try:
        val = _walk(keccak256(address), account_proof, root)
    except ValueError:
        return False
    return val is ABSENT


def verify_storage_inclusion(slot: bytes, storage_proof, root: bytes):
    """Return the canonical integer slot value, or None."""
    try:
        val = _walk(keccak256(slot), storage_proof, root)
    except ValueError:
        return None
    if val is ABSENT:
        return None
    # storage leaf stores RLP(trimmed-BE value)
    inner = rlp_decode(val)
    return be_to_int(inner)


def verify_storage_exclusion(slot: bytes, storage_proof, root: bytes) -> bool:
    try:
        val = _walk(keccak256(slot), storage_proof, root)
    except ValueError:
        return False
    return val is ABSENT


# ---------------------------------------------------------------------------
# Synthetic-trie builders (used by are_generate.py for the MINIMAL preset and by
# are_real_vectors.py is NOT needed — real vectors use real proofs). These build
# a REAL 2-leaf hexary trie node-by-node (branch + leaves) so the MINIMAL
# vectors exercise the same real hexary walker as the mainnet ones.
# ---------------------------------------------------------------------------

def _leaf_node(remaining_nibbles, value: bytes):
    # encode terminal leaf with hex-prefix (leaf flag = 2/3)
    odd = len(remaining_nibbles) & 1
    flag = (3 if odd else 2)
    nibs = [flag, (0 if not odd else remaining_nibbles[0])]
    body = remaining_nibbles[1:] if odd else remaining_nibbles
    # pack nibbles -> bytes
    if odd:
        first_byte = (flag << 4) | remaining_nibbles[0]
        rest = remaining_nibbles[1:]
    else:
        first_byte = (flag << 4)
        rest = remaining_nibbles
    packed = bytes([first_byte])
    for i in range(0, len(rest), 2):
        packed += bytes([(rest[i] << 4) | rest[i + 1]])
    return rlp_encode([packed, value])


def build_two_account_trie(addr_a: bytes, acct_a_rlp: bytes,
                           addr_b: bytes, acct_b_rlp: bytes):
    """Build a real hexary trie with two accounts that diverge at the first
    nibble (a single branch node with two leaf children). Returns
    (root, proof_for_a, proof_for_b, absent_proof_for_a_neighbour).

    Guarantees the two keys differ in nibble 0 (caller passes suitable addrs)."""
    ka = keccak256(addr_a)
    kb = keccak256(addr_b)
    na = _nibbles(ka)
    nb = _nibbles(kb)
    assert na[0] != nb[0], "addresses must diverge at nibble 0 for this builder"
    leaf_a = _leaf_node(na[1:], acct_a_rlp)
    leaf_b = _leaf_node(nb[1:], acct_b_rlp)
    branch = [b""] * 17
    branch[na[0]] = keccak256(leaf_a)
    branch[nb[0]] = keccak256(leaf_b)
    branch_node = rlp_encode(branch)
    root = keccak256(branch_node)
    proof_a = [branch_node, leaf_a]
    proof_b = [branch_node, leaf_b]
    return root, proof_a, proof_b


def build_two_storage_trie(slot_a: bytes, value_a_int: int,
                           slot_b: bytes, value_b_int: int):
    ka = keccak256(slot_a)
    kb = keccak256(slot_b)
    na = _nibbles(ka)
    nb = _nibbles(kb)
    assert na[0] != nb[0], "slots must diverge at nibble 0 for this builder"
    val_a = rlp_encode(be_trim(value_a_int))
    val_b = rlp_encode(be_trim(value_b_int))
    leaf_a = _leaf_node(na[1:], val_a)
    leaf_b = _leaf_node(nb[1:], val_b)
    branch = [b""] * 17
    branch[na[0]] = keccak256(leaf_a)
    branch[nb[0]] = keccak256(leaf_b)
    branch_node = rlp_encode(branch)
    root = keccak256(branch_node)
    return root, [branch_node, leaf_a], [branch_node, leaf_b]
