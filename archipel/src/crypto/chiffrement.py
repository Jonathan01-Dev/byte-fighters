"""
Chiffrement AES-256-GCM pour les messages
"""
import nacl.secret
import nacl.utils
import hashlib
import os

def deriver_cle_session(secret_partage, salt=None):
    """
    Dérive une clé de session à partir du secret partagé
    IMPORTANT: Doit être DÉTERMINISTE - même secret = même clé !
    
    Args:
        secret_partage: Le secret partagé (32 bytes)
        salt: Optionnel, mais doit être le même pour les deux !
    
    Returns:
        tuple: (cle_session, salt)
    """
    if salt is None:
        salt = b"archipel-handshake-salt-fixe"
    
    h = hashlib.sha256()
    h.update(secret_partage)
    h.update(salt)
    h.update(b"archipel-session-v1")
    
    return h.digest(), salt

def chiffrer_message(cle_session, message_clair):
    """
    Chiffre un message avec AES-256-GCM
    """
    if isinstance(message_clair, str):
        message_clair = message_clair.encode('utf-8')
    
    boite = nacl.secret.SecretBox(cle_session[:32])
    message_chiffre = boite.encrypt(message_clair)
    
    return message_chiffre

def dechiffrer_message(cle_session, message_chiffre):
    """
    Déchiffre un message avec AES-256-GCM
    """
    boite = nacl.secret.SecretBox(cle_session[:32])
    
    try:
        message_clair = boite.decrypt(message_chiffre)
        return message_clair
    except nacl.exceptions.CryptoError as e:
        print(f" Échec du déchiffrement: {e}")
        return None

def exemple_chiffrement():
    """
    Exemple pour comprendre
    """
    print(" Exemple de chiffrement AES-256-GCM")
    print("-" * 50)
    
    secret_partage = os.urandom(32)
    print(f" Secret partagé (simulé): {secret_partage.hex()[:32]}...")
    
    sel = b"salt-demo"
    cle_session1, _ = deriver_cle_session(secret_partage, sel)
    cle_session2, _ = deriver_cle_session(secret_partage, sel)
    
    print(f" Clé session 1: {cle_session1.hex()[:32]}...")
    print(f" Clé session 2: {cle_session2.hex()[:32]}...")
    
    if cle_session1 == cle_session2:
        print(f"Les clés sont identiques (bon !)")
    else:
        print(f" Les clés sont différentes (problème !)")
    
    message = "Coucou les amis ! Ce message est secret."
    print(f"\n Message original: '{message}'")
    
    message_chiffre = chiffrer_message(cle_session1, message)
    print(f" Message chiffré: {message_chiffre.hex()[:50]}...")
    
    message_dechiffre = dechiffrer_message(cle_session2, message_chiffre)
    
    if message_dechiffre is not None:
        message_dechiffre_texte = message_dechiffre.decode('utf-8')
        print(f" Message déchiffré: '{message_dechiffre_texte}'")
        
        if message == message_dechiffre_texte:
            print(f"\n Succès !")
    else:
        print(f"\n Échec")

if __name__ == "__main__":
    exemple_chiffrement()
    