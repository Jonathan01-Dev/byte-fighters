"""
Échange de clés X25519 (ECDH)
Version ultra-simple avec PyNaCl
"""
import nacl.public
import nacl.utils

def generer_cle_ephemere():
    """
    Génère une paire de clés éphémère X25519
    """
    cle_privee = nacl.public.PrivateKey.generate()
    
    cle_publique = cle_privee.public_key
    
    return {
        'privee': bytes(cle_privee),
        'publique': bytes(cle_publique)
    }

def calculer_secret_partage(ma_cle_privee_bytes, sa_cle_publique_bytes):
    """
    Calcule le secret partagé entre deux nœuds
    """
    try:
        ma_privee = nacl.public.PrivateKey(ma_cle_privee_bytes)
        sa_publique = nacl.public.PublicKey(sa_cle_publique_bytes)
        
        boite = nacl.public.Box(ma_privee, sa_publique)
        secret = boite.shared_key()
        
        return secret
        
    except Exception as e:
        print(f"Erreur calcul secret: {e}")
        return None

def exemple():
    """
    Exemple simple qui devrait fonctionner
    """
    print(" Test échange de clés")
    print("-" * 40)
    
    alice = generer_cle_ephemere()
    print(f"Alice - clé publique: {alice['publique'].hex()[:16]}...")
    
    bob = generer_cle_ephemere()
    print(f"Bob   - clé publique: {bob['publique'].hex()[:16]}...")
    
    print("\nCalcul des secrets...")
    
    secret_alice = calculer_secret_partage(alice['privee'], bob['publique'])
    secret_bob = calculer_secret_partage(bob['privee'], alice['publique'])
    
    if secret_alice and secret_bob:
        print(f"\nSecret Alice: {secret_alice.hex()[:32]}...")
        print(f"Secret Bob:   {secret_bob.hex()[:32]}...")
        
        if secret_alice == secret_bob:
            print("\n SUCCÈS ! Les secrets sont identiques !")
            return True
        else:
            print("\n ÉCHEC ! Les secrets sont différents")
            return False
    else:
        print("\n ÉCHEC ! Impossible de calculer les secrets")
        return False

if __name__ == "__main__":
    exemple()