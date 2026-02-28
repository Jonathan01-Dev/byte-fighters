from utils.packet import build_packet, parse_packet
import os

def test_packet():
    node_id = os.urandom(32)
    payload = b"Hello Archipel"

    # Test 1 — Paquet valide
    print("=" * 50)
    print("TEST 1 : Paquet valide")
    packet = build_packet(0x01, node_id, payload)
    print("Packet built:", packet.hex())
    parsed = parse_packet(packet)
    print("Parsed:", parsed)

    # Test 2 — Paquet corrompu (modification d'un byte)
    print("\n" + "=" * 50)
    print("TEST 2 : Paquet corrompu (byte 10 modifié)")
    corrupted = bytearray(packet)   # convertit en tableau mutable
    corrupted[10] ^= 0xFF           # flip tous les bits du byte 10
    try:
        parsed_corrupted = parse_packet(bytes(corrupted))  # reconvertit en bytes
        print("Parsed (ne devrait pas arriver):", parsed_corrupted)
    except ValueError as e:
        print(f"Erreur attendue : {e}")


if __name__ == "__main__":
    test_packet()