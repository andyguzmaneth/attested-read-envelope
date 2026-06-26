"""
Vector (JSON) codec: serialize envelope/anchor objects to the vector schema and
load them back into objects the verifier consumes.

Hex convention: all byte fields are "0x"-prefixed lowercase hex. Lists of bytes
are lists of hex strings. Booleans as JSON bools, ints as JSON numbers.
"""

from are_ssz import BeaconBlockHeader, ExecutionPayloadHeader


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def unhx(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


class ReadProof:
    def __init__(self, read_kind, address, slot, value, account_proof,
                 storage_proof, presence, declared_state_root=None):
        self.read_kind = read_kind
        self.address = address
        self.slot = slot
        self.value = value
        self.account_proof = account_proof
        self.storage_proof = storage_proof
        self.presence = presence
        self.declared_state_root = declared_state_root


class Envelope:
    def __init__(self, version, chain_id, anchor_type, settlement_layer,
                 block_number, beacon_slot, timestamp, state_root, proof_format,
                 finality_status, anchor_ref, reads, sig_alg=0,
                 provider_sig=b"", provider_key_hint=b""):
        self.version = version
        self.chain_id = chain_id
        self.anchor_type = anchor_type
        self.settlement_layer = settlement_layer
        self.block_number = block_number
        self.beacon_slot = beacon_slot
        self.timestamp = timestamp
        self.state_root = state_root
        self.proof_format = proof_format
        self.finality_status = finality_status
        self.anchor_ref = anchor_ref
        self.reads = reads
        self.sig_alg = sig_alg
        self.provider_sig = provider_sig
        self.provider_key_hint = provider_key_hint


class ConsensusAnchor:
    def __init__(self, attested_header, signature_slot, sync_committee_bits,
                 sync_committee_signature, read_block_header, execution_header,
                 execution_branch, has_finality, finalized_header,
                 finality_branch, ancestor_proof):
        self.attested_header = attested_header
        self.signature_slot = signature_slot
        self.sync_committee_bits = sync_committee_bits
        self.sync_committee_signature = sync_committee_signature
        self.read_block_header = read_block_header
        self.execution_header = execution_header
        self.execution_branch = execution_branch
        self.has_finality = has_finality
        self.finalized_header = finalized_header
        self.finality_branch = finality_branch
        self.ancestor_proof = ancestor_proof


# ---------------------------------------------------------------------------
# header / exec-header (de)serialization
# ---------------------------------------------------------------------------

def header_to_json(h: BeaconBlockHeader):
    return {
        "slot": h.slot, "proposer_index": h.proposer_index,
        "parent_root": hx(h.parent_root), "state_root": hx(h.state_root),
        "body_root": hx(h.body_root),
    }


def header_from_json(j):
    return BeaconBlockHeader(j["slot"], j["proposer_index"],
                             unhx(j["parent_root"]), unhx(j["state_root"]),
                             unhx(j["body_root"]))


def exec_to_json(x: ExecutionPayloadHeader):
    # FULL 17-field ExecutionPayloadHeader (v0.5).
    return {
        "parent_hash": hx(x.parent_hash),
        "fee_recipient": hx(x.fee_recipient),
        "state_root": hx(x.state_root),
        "receipts_root": hx(x.receipts_root),
        "logs_bloom": hx(x.logs_bloom),
        "prev_randao": hx(x.prev_randao),
        "block_number": x.block_number,
        "gas_limit": x.gas_limit,
        "gas_used": x.gas_used,
        "timestamp": x.timestamp,
        "extra_data": hx(x.extra_data),
        "base_fee_per_gas": str(x.base_fee_per_gas),  # uint256 -> string (JSON-safe)
        "block_hash": hx(x.block_hash),
        "transactions_root": hx(x.transactions_root),
        "withdrawals_root": hx(x.withdrawals_root),
        "blob_gas_used": x.blob_gas_used,
        "excess_blob_gas": x.excess_blob_gas,
    }


def exec_from_json(j):
    return ExecutionPayloadHeader(
        state_root=unhx(j["state_root"]),
        block_number=j["block_number"],
        timestamp=j["timestamp"],
        parent_hash=unhx(j["parent_hash"]),
        fee_recipient=unhx(j["fee_recipient"]),
        receipts_root=unhx(j["receipts_root"]),
        logs_bloom=unhx(j["logs_bloom"]),
        prev_randao=unhx(j["prev_randao"]),
        gas_limit=j["gas_limit"],
        gas_used=j["gas_used"],
        extra_data=unhx(j["extra_data"]),
        base_fee_per_gas=int(j["base_fee_per_gas"]),
        block_hash=unhx(j["block_hash"]),
        transactions_root=unhx(j["transactions_root"]),
        withdrawals_root=unhx(j["withdrawals_root"]),
        blob_gas_used=j["blob_gas_used"],
        excess_blob_gas=j["excess_blob_gas"],
    )


def anchor_to_json(a: ConsensusAnchor):
    return {
        "attested_header": header_to_json(a.attested_header),
        "signature_slot": a.signature_slot,
        "sync_committee_bits": [bool(b) for b in a.sync_committee_bits],
        "sync_committee_signature": hx(a.sync_committee_signature),
        "read_block_header": header_to_json(a.read_block_header),
        "execution_header": exec_to_json(a.execution_header),
        "execution_branch": [hx(x) for x in a.execution_branch],
        "has_finality": a.has_finality,
        "finalized_header": header_to_json(a.finalized_header),
        "finality_branch": [hx(x) for x in a.finality_branch],
        "ancestor_proof": [hx(x) for x in a.ancestor_proof],
    }


def anchor_from_json(j):
    return ConsensusAnchor(
        header_from_json(j["attested_header"]),
        j["signature_slot"],
        [bool(b) for b in j["sync_committee_bits"]],
        unhx(j["sync_committee_signature"]),
        header_from_json(j["read_block_header"]),
        exec_from_json(j["execution_header"]),
        [unhx(x) for x in j["execution_branch"]],
        j["has_finality"],
        header_from_json(j["finalized_header"]),
        [unhx(x) for x in j["finality_branch"]],
        [unhx(x) for x in j["ancestor_proof"]],
    )


def read_to_json(r: ReadProof):
    d = {
        "read_kind": r.read_kind, "address": hx(r.address), "slot": hx(r.slot),
        "value": hx(r.value),
        "account_proof": [hx(x) for x in r.account_proof],
        "storage_proof": [hx(x) for x in r.storage_proof],
        "presence": r.presence,
    }
    if r.declared_state_root is not None:
        d["declared_state_root"] = hx(r.declared_state_root)
    return d


def read_from_json(j):
    return ReadProof(
        j["read_kind"], unhx(j["address"]), unhx(j["slot"]), unhx(j["value"]),
        [unhx(x) for x in j["account_proof"]],
        [unhx(x) for x in j["storage_proof"]],
        j["presence"],
        unhx(j["declared_state_root"]) if "declared_state_root" in j else None,
    )


def envelope_to_json(e: Envelope):
    return {
        "version": e.version, "chain_id": e.chain_id,
        "anchor_type": e.anchor_type, "settlement_layer": e.settlement_layer,
        "block_number": e.block_number, "beacon_slot": e.beacon_slot,
        "timestamp": e.timestamp, "state_root": hx(e.state_root),
        "proof_format": list(e.proof_format),
        "finality_status": e.finality_status,
        "anchor_ref": hx(e.anchor_ref),
        "reads": [read_to_json(r) for r in e.reads],
        "sig_alg": e.sig_alg, "provider_sig": hx(e.provider_sig),
        "provider_key_hint": hx(e.provider_key_hint),
    }


def envelope_from_json(j):
    return Envelope(
        j["version"], j["chain_id"], j["anchor_type"], j["settlement_layer"],
        j["block_number"], j["beacon_slot"], j["timestamp"],
        unhx(j["state_root"]), tuple(j["proof_format"]), j["finality_status"],
        unhx(j["anchor_ref"]), [read_from_json(r) for r in j["reads"]],
        j["sig_alg"], unhx(j["provider_sig"]), unhx(j["provider_key_hint"]),
    )
