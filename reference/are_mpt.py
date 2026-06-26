"""
EIP-1186 Merkle-Patricia proof primitives for the ARE reference impl.

Real cryptography: Keccak-256 (Ethereum variant, via pycryptodome) over
RLP-encoded trie nodes. Account/storage values are RLP-encoded per the
Ethereum state-trie layout.

HONEST SIMPLIFICATION (documented in reference/README.md): the fixtures use a
*single-account* MPT. The trie therefore collapses to a single leaf node whose
key is keccak256(address) and whose value is the RLP account list. The
"state_root" is keccak256(RLP(leaf_node)). This exercises the real EIP-1186
node-decoding and keccak/RLP machinery and proves inclusion/exclusion logic
end-to-end, but it is NOT a full hexary trie with branch/extension nodes (no
fabricated intermediate hashes — every node hash is a real keccak over real
RLP). A full-MPT fixture is deferred to `draft` (see spec §Implementation Notes).
"""

from Crypto.Hash import keccak


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
# Minimal RLP encode/decode (sufficient for trie nodes + account/storage values)
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

EMPTY_STORAGE_ROOT = keccak256(rlp_encode(b""))   # keccak of RLP("") == empty trie root sentinel here
EMPTY_CODE_HASH = keccak256(b"")


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
# Single-account "leaf" trie (documented simplification)
# A node is RLP([path_key, value]); state_root = keccak256(RLP(node)).
# account_proof is the single-element list [RLP(node)].
# ---------------------------------------------------------------------------

def build_single_account_trie(address: bytes, account_rlp: bytes):
    key = keccak256(address)
    node = rlp_encode([key, account_rlp])
    root = keccak256(node)
    return root, [node]


def verify_account_inclusion(address: bytes, account_proof, root: bytes):
    """Return decoded account dict, or None if absent / proof invalid."""
    if not account_proof:
        return None
    node = account_proof[0]
    if keccak256(node) != root:
        return None
    decoded = rlp_decode(node)
    if not isinstance(decoded, list) or len(decoded) != 2:
        return None
    key, value = decoded
    if key != keccak256(address):
        return None  # path does not lead to this address
    return decode_account(value)


def verify_account_exclusion(address: bytes, account_proof, root: bytes) -> bool:
    """The single-account proof commits a DIFFERENT key; the path for `address`
    terminates at a node whose stored key != keccak256(address) -> divergent
    path -> proven absence. We verify the node hashes to root and that the
    committed key genuinely differs (a real terminal/divergent-path proof, not a
    truncated one)."""
    if not account_proof:
        return False
    node = account_proof[0]
    if keccak256(node) != root:
        return False
    decoded = rlp_decode(node)
    if not isinstance(decoded, list) or len(decoded) != 2:
        return False
    key, _value = decoded
    return key != keccak256(address)


def build_single_storage_trie(slot: bytes, value_int: int):
    key = keccak256(slot)
    stored = rlp_encode(be_trim(value_int))   # EIP-1186 stores RLP(trimmed BE)
    node = rlp_encode([key, stored])
    root = keccak256(node)
    return root, [node]


def verify_storage_inclusion(slot: bytes, storage_proof, root: bytes):
    """Return the canonical 32-byte slot value, or None."""
    if not storage_proof:
        return None
    node = storage_proof[0]
    if keccak256(node) != root:
        return None
    decoded = rlp_decode(node)
    if not isinstance(decoded, list) or len(decoded) != 2:
        return None
    key, stored = decoded
    if key != keccak256(slot):
        return None
    inner = rlp_decode(stored)   # RLP-decode the trimmed BE value
    return be_to_int(inner)


def verify_storage_exclusion(slot: bytes, storage_proof, root: bytes) -> bool:
    if not storage_proof:
        return False
    node = storage_proof[0]
    if keccak256(node) != root:
        return False
    decoded = rlp_decode(node)
    if not isinstance(decoded, list) or len(decoded) != 2:
        return False
    key, _stored = decoded
    return key != keccak256(slot)
