import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from crypto.init import get_ou_creer_identite
from crypto.keys import cle_en_hex
import nacl.signing
import nacl.encoding
import nacl.exceptions

_IDENTITE = None

def _get_identite():
    """Charge l'identité une seule fois"""
    global _IDENTITE
    if _IDENTITE is None:
        _IDENTITE = get_ou_creer_identite()
    return _IDENTITE

def get_node_id():
    """Retourne l'identifiant public du nœud"""
    return _get_identite()['publique']

def get_node_id_hex():
    """Retourne l'ID en hexadécimal pour affichage"""
    return cle_en_hex(get_node_id())

def signer(message):
    """Signe un message"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    identite = _get_identite()
    cle_privee = nacl.signing.SigningKey(identite['privee'])
    message_signe = cle_privee.sign(message)
    return message_signe.signature

def verifier(cle_publique_bytes, message, signature_bytes):
    """Vérifie une signature"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    try:
        cle_verif = nacl.signing.VerifyKey(cle_publique_bytes)
        cle_verif.verify(message, signature_bytes)
        return True
    except nacl.exceptions.BadSignatureError:
        return False

def debug_crypto():
    """Affiche les infos pour le debug"""
    identite = _get_identite()
    pub_hex = cle_en_hex(identite['publique'])
    print("\n État de la crypto:")
    print(f"   • Node ID: {pub_hex[:32]}...")