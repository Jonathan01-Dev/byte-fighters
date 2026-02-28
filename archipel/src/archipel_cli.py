"""
Interface CLI pour Archipel
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from crypto.init import get_ou_creer_identite
from crypto.keys import cle_en_hex
from src.crypto.manifest import Manifest
from crypto.hash import sha256_chunk, verifier_chunk
from node import get_node_id_hex, signer, verifier

def cmd_identity():
    """Affiche l'identité du nœud"""
    print("\n IDENTITÉ DU NŒUD")
    print("=" * 50)
    identite = get_ou_creer_identite()
    print(f"Node ID: {cle_en_hex(identite['publique'])}")
    print(f"Fichier: {os.path.expanduser('~')}\\.archipel\\identity.json")
    print("=" * 50)

def cmd_send(fichier):
    """Prépare un fichier à envoyer"""
    print(f"\n PRÉPARATION DU FICHIER: {fichier}")
    print("=" * 50)
    
    if not os.path.exists(fichier):
        print(f" Fichier {fichier} introuvable")
        return
    
    manifest = Manifest(fichier, chunk_size=524288)
    manifest.signer()
    
    manifest_file = f"{fichier}.manifest.json"
    manifest.sauvegarder(manifest_file)
    
    print(f"\n Fichier prêt à être partagé")
    print(f" Manifest: {manifest_file}")
    print(f" Taille: {manifest.data['size']} bytes")
    print(f" Chunks: {manifest.data['nb_chunks']}")
    print("=" * 50)

def cmd_handshake_demo():
    """Démontre un handshake"""
    print("\n DÉMO HANDSHAKE")
    print("=" * 50)
    
    from crypto.handshake import exemple_handshake
    exemple_handshake()

def cmd_help():
    """Affiche l'aide"""
    print("\n ARCHIPEL - AIDE")
    print("=" * 50)
    print("Commandes disponibles:")
    print("  identity    - Affiche l'identité du nœud")
    print("  send <file> - Prépare un fichier à envoyer")
    print("  handshake   - Démonstration du handshake")
    print("  help        - Affiche cette aide")
    print("=" * 50)

def main():
    """Point d'entrée principal"""
    if len(sys.argv) < 2:
        cmd_help()
        return
    
    commande = sys.argv[1]
    
    if commande == "identity":
        cmd_identity()
    elif commande == "send" and len(sys.argv) > 2:
        cmd_send(sys.argv[2])
    elif commande == "handshake":
        cmd_handshake_demo()
    else:
        cmd_help()

if __name__ == "__main__":
    main()