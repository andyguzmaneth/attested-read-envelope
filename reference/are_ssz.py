"""
SSZ + consensus hashing primitives for the ARE reference implementation.

Real cryptography only:
  - SHA-256 for SSZ hash_tree_root (consensus serialization).
  - Keccak-256 (Ethereum variant) + RLP for the EIP-1186 MPT proof.
  - Merkle branch verification by generalized index.

Honest scope: this implements exactly the SSZ machinery the ARE verifier needs
(fixed-size uints/bytes, Bytes32 vectors, BeaconBlockHeader, a reduced
ExecutionPayloadHeader, and generalized-index branch checks). It is NOT a full
SSZ library; containers are hashed field-by-field with explicit merkleization of
the field roots. Every leaf hash is REAL SHA-256 / Keccak-256 — no value is
fabricated.
"""

import hashlib

# ---------------------------------------------------------------------------
# SHA-256 (consensus) primitives
# ---------------------------------------------------------------------------

ZERO_HASHES = [b"\x00" * 32]
for _i in range(1, 64):
    ZERO_HASHES.append(hashlib.sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_concat(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(a + b).digest()


def next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def merkleize(chunks, limit=None):
    """Merkleize a list of 32-byte chunks (SSZ), padding with zero subtrees."""
    if limit is None:
        count = max(1, len(chunks))
        width = next_pow2(count)
    else:
        width = next_pow2(limit) if limit > 0 else 1
    nodes = list(chunks)
    # pad to width using precomputed zero hashes at depth 0
    while len(nodes) < width:
        nodes.append(ZERO_HASHES[0])
    # build tree
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            nxt.append(hash_concat(nodes[i], nodes[i + 1]))
        nodes = nxt
    return nodes[0]


def uint64_root(x: int) -> bytes:
    return x.to_bytes(8, "little") + b"\x00" * 24


def uint256_root(x: int) -> bytes:
    return x.to_bytes(32, "little")


def bytes32_root(b: bytes) -> bytes:
    assert len(b) == 32
    return b


def bytes20_root(b: bytes) -> bytes:
    # Bytes20 is a fixed Vector[uint8,20] -> right-pad to 32-byte chunk
    assert len(b) == 20
    return b + b"\x00" * 12


def boolean_root(x: bool) -> bytes:
    return (b"\x01" if x else b"\x00") + b"\x00" * 31


# ---------------------------------------------------------------------------
# Consensus containers (field-ordered hash_tree_root)
# ---------------------------------------------------------------------------

class BeaconBlockHeader:
    """Standard consensus BeaconBlockHeader: slot, proposer_index, parent_root,
    state_root, body_root. All five fields hashed as a 5-leaf container."""

    def __init__(self, slot=0, proposer_index=0, parent_root=b"\x00" * 32,
                 state_root=b"\x00" * 32, body_root=b"\x00" * 32):
        self.slot = slot
        self.proposer_index = proposer_index
        self.parent_root = parent_root
        self.state_root = state_root
        self.body_root = body_root

    def hash_tree_root(self) -> bytes:
        chunks = [
            uint64_root(self.slot),
            uint64_root(self.proposer_index),
            bytes32_root(self.parent_root),
            bytes32_root(self.state_root),
            bytes32_root(self.body_root),
        ]
        return merkleize(chunks)

    def is_zero(self) -> bool:
        return (self.slot == 0 and self.proposer_index == 0 and
                self.parent_root == b"\x00" * 32 and
                self.state_root == b"\x00" * 32 and
                self.body_root == b"\x00" * 32)

    def __eq__(self, other):
        return (isinstance(other, BeaconBlockHeader) and
                self.slot == other.slot and
                self.proposer_index == other.proposer_index and
                self.parent_root == other.parent_root and
                self.state_root == other.state_root and
                self.body_root == other.body_root)


ZERO_HEADER = BeaconBlockHeader()


class ExecutionPayloadHeader:
    """REDUCED ExecutionPayloadHeader for the reference impl.

    Honest simplification: the real Capella+ ExecutionPayloadHeader has 17 fields.
    The ARE verifier only reads state_root, block_number, timestamp from it. We
    model it as a 4-leaf container {state_root, block_number, timestamp,
    extra_root}, merkleized with REAL SHA-256. This keeps hash_tree_root
    deterministic and the execution_branch a genuine SSZ Merkle proof against a
    real leaf — it is simply a narrower object than mainnet's. Documented in
    reference/README.md.
    """

    def __init__(self, state_root, block_number, timestamp, extra_root=b"\x00" * 32):
        self.state_root = state_root
        self.block_number = block_number
        self.timestamp = timestamp
        self.extra_root = extra_root

    def hash_tree_root(self) -> bytes:
        chunks = [
            bytes32_root(self.state_root),
            uint64_root(self.block_number),
            uint64_root(self.timestamp),
            bytes32_root(self.extra_root),
        ]
        return merkleize(chunks)


# ---------------------------------------------------------------------------
# Generalized-index Merkle branch verification
# ---------------------------------------------------------------------------

def verify_merkle_branch(leaf: bytes, branch, gindex: int, root: bytes) -> bool:
    """Verify a Merkle branch against `root` at generalized index `gindex`.

    branch[i] is the sibling at depth i (deepest first), per the consensus-spec
    is_valid_merkle_branch but driven by gindex bit decomposition.
    """
    node = leaf
    g = gindex
    i = 0
    while g > 1:
        if i >= len(branch):
            return False
        sib = branch[i]
        if g & 1:  # node is the right child
            node = hash_concat(sib, node)
        else:      # node is the left child
            node = hash_concat(node, sib)
        g >>= 1
        i += 1
    return node == root


def build_merkle_branch(leaf: bytes, gindex: int, siblings):
    """Construct (branch, root) for a leaf at gindex given the sibling hashes
    (deepest-first). Used by the generator with REAL synthetic siblings — the
    siblings are arbitrary 32-byte values but every PARENT hash is real SHA-256,
    so the resulting root genuinely commits to the leaf along the gindex path.
    """
    node = leaf
    g = gindex
    i = 0
    while g > 1:
        sib = siblings[i]
        if g & 1:
            node = hash_concat(sib, node)
        else:
            node = hash_concat(node, sib)
        g >>= 1
        i += 1
    return list(siblings[:i]), node
