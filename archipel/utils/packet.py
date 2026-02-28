import struct
import hmac
import hashlib
from utils.constants import MAGIC, HMAC_KEY


def build_packet(packet_type: int, node_id: bytes, payload: bytes) -> bytes:
    """
    Construit un paquet Archipel
    """

    if len(node_id) != 32:
        raise ValueError("node_id must be 32 bytes")

    # Header
    header = MAGIC
    header += struct.pack("!B", packet_type)
    header += node_id
    header += struct.pack("!I", len(payload))

    body = header + payload

    # HMAC
    signature = hmac.new(HMAC_KEY, body, hashlib.sha256).digest()

    return body + signature


def parse_packet(data: bytes) -> dict:
    """
    Parse et vérifie un paquet Archipel
    """

    if len(data) < 73:  # minimum possible
        raise ValueError("Packet too short")

    magic = data[:4]
    if magic != MAGIC:
        raise ValueError("Invalid MAGIC header")

    packet_type = struct.unpack("!B", data[4:5])[0]
    node_id = data[5:37]
    payload_len = struct.unpack("!I", data[37:41])[0]

    payload_start = 41
    payload_end = payload_start + payload_len

    payload = data[payload_start:payload_end]
    received_hmac = data[payload_end:]

    # Vérifier HMAC
    computed_hmac = hmac.new(
        HMAC_KEY,
        data[:payload_end],
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_hmac, computed_hmac):
        raise ValueError("HMAC verification failed")

    return {
        "type": packet_type,
        "node_id": node_id,
        "payload": payload
    }
