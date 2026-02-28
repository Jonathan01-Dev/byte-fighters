import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import nacl.signing
import nacl.encoding

def generer_cles():
    """
    Génère une paire de clés Ed25519
    """
    cle_privee = nacl.signing.SigningKey.generate()
    
    cle_publique = cle_privee.verify_key
    
    return {
        'publique': bytes(cle_publique),    # 32 bytes
        'privee': bytes(cle_privee)         # 64 bytes
    }

def cle_en_hex(cle_bytes):
    """
    Convertit une clé en hexadécimal (pour l'affichage)
    """
    return nacl.encoding.HexEncoder.encode(cle_bytes).decode('utf-8')