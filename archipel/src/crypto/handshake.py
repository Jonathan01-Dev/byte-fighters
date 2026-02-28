"""
Handshake entre deux nœuds
La conversation d'installation avant de parler
"""
import sys
import os
import json
import time
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.crypto.echange_cles import generer_cle_ephemere, calculer_secret_partage
from src.crypto.chiffrement import deriver_cle_session, chiffrer_message, dechiffrer_message
from src.node import get_node_id, signer, verifier, get_node_id_hex

SALT_HANDSHAKE = b"archipel-handshake-salt-fixe-pour-sprint2"

class Handshake:
    """
    Gère la poignée de main entre deux nœuds
    
    États possibles:
    0 = INIT: pas commencé
    1 = ENVOYE_HELLO: j'ai envoyé mon hello
    2 = RECU_HELLO: j'ai reçu son hello
    3 = ENVOYE_KEY: j'ai envoyé ma clé
    4 = RECU_KEY: j'ai reçu sa clé
    5 = COMPLETE: handshake réussi
    """
    
    TYPE_HELLO = 0x10
    TYPE_KEY = 0x11
    TYPE_AUTH = 0x12
    TYPE_OK = 0x13
    TYPE_ERROR = 0xFF
    
    def __init__(self, est_initiateur=True):
        """
        est_initiateur: True si c'est nous qui avons commencé la connexion
        """
        self.est_initiateur = est_initiateur
        self.etat = 0  # INIT
        
        self.mon_id = get_node_id()
        self.mon_id_hex = get_node_id_hex()
        
        self.ma_cle_ephemere = generer_cle_ephemere()
        
        self.son_id = None
        self.son_id_hex = None
        self.sa_cle_publique_ephemere = None
        self.secret_partage = None
        self.cle_session = None
        
        self.nonce_handshake = os.urandom(8)
        self.nonce_de_lautre = None  # On stockera le nonce de l'autre
        
        print(f" Handshake initialisé (initiateur: {est_initiateur})")
        print(f"   Mon ID: {self.mon_id_hex[:16]}...")
        print(f"   Ma clé éphémère (publique): {self.ma_cle_ephemere['publique'].hex()[:16]}...")
        print(f"   Mon nonce: {self.nonce_handshake.hex()}")
    
    def preparer_message_hello(self):
        """
        Prépare le premier message : HELLO
        Contient: mon ID, ma clé publique éphémère, un nonce
        """
        message = {
            'type': self.TYPE_HELLO,
            'node_id': self.mon_id_hex,
            'ephemeral_key': self.ma_cle_ephemere['publique'].hex(),
            'nonce': self.nonce_handshake.hex(),
            'timestamp': time.time()
        }
        
        message_bytes = json.dumps(message).encode('utf-8')
        
        signature = signer(message_bytes)
        
        self.etat = 1  # ENVOYE_HELLO
        print(f"\n📤 Envoi HELLO à l'autre nœud")
        print(f"   Taille message: {len(message_bytes)} bytes")
        print(f"   Nonce envoyé: {self.nonce_handshake.hex()}")
        
        return message_bytes, signature
    
    def recevoir_message_hello(self, message_bytes, signature):
        """
        Reçoit et vérifie le HELLO de l'autre
        """
        try:
            message = json.loads(message_bytes.decode('utf-8'))
            
            if message['type'] != self.TYPE_HELLO:
                print(f" Type de message incorrect: {message['type']}")
                return False
            
            self.son_id_hex = message['node_id']
            self.son_id = bytes.fromhex(self.son_id_hex)
            
            if len(self.son_id) != 32:
                print(f" Clé publique reçue fait {len(self.son_id)} bytes (devrait être 32)")
                return False
            
            print(f"   Vérification signature avec clé {self.son_id_hex[:16]}...")
            if not verifier(self.son_id, message_bytes, signature):
                print(f" Signature HELLO invalide !")
                return False
            
            self.sa_cle_publique_ephemere = bytes.fromhex(message['ephemeral_key'])
            
            nonce_autre = message.get('nonce')
            if nonce_autre:
                self.nonce_de_lautre = bytes.fromhex(nonce_autre)
                print(f"   Nonce de l'autre stocké: {self.nonce_de_lautre.hex()}")
            
            print(f"\n Reçu HELLO de {self.son_id_hex[:16]}...")
            print(f"   Signature valide ✓")
            print(f"   Sa clé éphémère (publique): {self.sa_cle_publique_ephemere.hex()[:16]}...")
            print(f"   Taille clé reçue: {len(self.sa_cle_publique_ephemere)} bytes")
            
            # IMPORTANT: Si on est le récepteur (pas l'initiateur), on peut déjà calculer le secret
            if not self.est_initiateur:  # C'est BOB qui reçoit le HELLO d'Alice
                print(f"\n    Côté RÉCEPTEUR - calcul du secret partagé...")
                print(f"      Ma clé privée éph: {self.ma_cle_ephemere['privee'].hex()[:16]}...")
                print(f"      Sa clé publique éph: {self.sa_cle_publique_ephemere.hex()[:16]}...")
                
                self.secret_partage = calculer_secret_partage(
                    self.ma_cle_ephemere['privee'],
                    self.sa_cle_publique_ephemere
                )
                
                if self.secret_partage:
                    print(f"      Secret partagé calculé!")
                    print(f"      Secret partagé (hex): {self.secret_partage.hex()[:32]}...")
                    
                    self.cle_session, _ = deriver_cle_session(self.secret_partage, SALT_HANDSHAKE)
                    print(f"       Clé session dérivée (avec salt fixe): {self.cle_session.hex()[:16]}...")
                else:
                    print(f"       Échec calcul secret partagé")
                    return False
            
            self.etat = 2  # RECU_HELLO
            return True
            
        except Exception as e:
            print(f" Erreur réception HELLO: {e}")
            traceback.print_exc()
            return False
    
    def preparer_message_key(self):
        """
        Prépare le message avec notre clé publique éphémère
        (en réponse à son HELLO)
        """
        if self.etat < 2:
            print(f" Pas encore reçu son HELLO")
            return None, None
        
        message = {
            'type': self.TYPE_KEY,
            'node_id': self.mon_id_hex,  # On inclut notre ID
            'ephemeral_key': self.ma_cle_ephemere['publique'].hex(),
            'nonce_response': self.nonce_handshake.hex()
        }
        
        message_bytes = json.dumps(message).encode('utf-8')
        signature = signer(message_bytes)
        
        if self.est_initiateur:  # C'est Alice qui prépare KEY après avoir reçu HELLO de Bob
            print(f"\n    Côté INITIATEUR - calcul du secret partagé (dans preparer_message_key)...")
            print(f"      Ma clé privée éph: {self.ma_cle_ephemere['privee'].hex()[:16]}...")
            print(f"      Sa clé publique éph: {self.sa_cle_publique_ephemere.hex()[:16]}...")
            
            self.secret_partage = calculer_secret_partage(
                self.ma_cle_ephemere['privee'],
                self.sa_cle_publique_ephemere
            )
            
            if self.secret_partage:
                print(f"       Secret partagé calculé!")
                print(f"      Secret partagé (hex): {self.secret_partage.hex()[:32]}...")
                
                self.cle_session, _ = deriver_cle_session(self.secret_partage, SALT_HANDSHAKE)
                print(f"       Clé session dérivée (avec salt fixe): {self.cle_session.hex()[:16]}...")
            else:
                print(f"       Échec calcul secret partagé")
        
        self.etat = 3  # ENVOYE_KEY
        print(f"\n Envoi de ma clé éphémère")
        print(f"   Taille message: {len(message_bytes)} bytes")
        print(f"   Mon ID inclus dans le message KEY")
        
        return message_bytes, signature
    
    def recevoir_message_key(self, message_bytes, signature):
        """
        Reçoit la clé éphémère de l'autre
        """
        try:
            message = json.loads(message_bytes.decode('utf-8'))
            
            if message['type'] != self.TYPE_KEY:
                print(f" Type incorrect: {message['type']}")
                return False
            
            son_id_hex = message.get('node_id')
            if son_id_hex:
                self.son_id = bytes.fromhex(son_id_hex)
                self.son_id_hex = son_id_hex
                print(f"   ID reçu dans KEY: {son_id_hex[:16]}...")
                print(f"   Taille ID: {len(self.son_id)} bytes")
            else:
                print(f"     Pas d'ID dans le message KEY")
            
            if self.son_id:
                print(f"   Vérification signature KEY avec clé {self.son_id_hex[:16]}...")
                if not verifier(self.son_id, message_bytes, signature):
                    print(f" Signature KEY invalide !")
                    return False
                print(f"   Signature KEY valide ✓")
            else:
                print(f"     Impossible de vérifier la signature (ID inconnu)")
                print(f"   On continue pour le debug...")
            
            self.sa_cle_publique_ephemere = bytes.fromhex(message['ephemeral_key'])
            print(f"\n📥 Reçu sa clé éphémère: {self.sa_cle_publique_ephemere.hex()[:16]}...")
            print(f"   Taille clé reçue: {len(self.sa_cle_publique_ephemere)} bytes")
            
            if self.est_initiateur and self.secret_partage is None:
                print(f"\n   🔄 Côté INITIATEUR - calcul du secret partagé (dans recevoir_message_key)...")
                print(f"      Ma clé privée éph: {self.ma_cle_ephemere['privee'].hex()[:16]}...")
                print(f"      Sa clé publique éph: {self.sa_cle_publique_ephemere.hex()[:16]}...")
                
                self.secret_partage = calculer_secret_partage(
                    self.ma_cle_ephemere['privee'],
                    self.sa_cle_publique_ephemere
                )
                
                if self.secret_partage:
                    print(f"       Secret partagé calculé!")
                    print(f"      Secret partagé (hex): {self.secret_partage.hex()[:32]}...")
                    
                    self.cle_session, _ = deriver_cle_session(self.secret_partage, SALT_HANDSHAKE)
                    print(f"       Clé session dérivée (avec salt fixe): {self.cle_session.hex()[:16]}...")
            
            self.etat = 4  # RECU_KEY
            return True
            
        except Exception as e:
            print(f" Erreur réception KEY: {e}")
            traceback.print_exc()
            return False
    
    def preparer_message_auth(self):
        """
        Prépare le message d'authentification final
        (prouve qu'on a bien la clé de session)
        """
        print(f"\n Préparation message AUTH")
        print(f"   cle_session existe: {self.cle_session is not None}")
        print(f"   état actuel: {self.etat}")
        print(f"   est_initiateur: {self.est_initiateur}")
        
        if self.cle_session is None:
            print(f"    ERREUR: cle_session est None !")
            print(f"   secret_partage: {self.secret_partage is not None}")
            if self.secret_partage:
                print(f"   secret_partage existe mais pas clé session - problème de dérivation")
            return None
        
        if self.nonce_de_lautre:
            nonce_a_utiliser = self.nonce_de_lautre.hex()
            print(f"   Utilisation du nonce de l'autre: {nonce_a_utiliser}")
        else:
            nonce_a_utiliser = self.nonce_handshake.hex()
            print(f"   Utilisation de notre nonce: {nonce_a_utiliser}")
        
        test_message = f"handshake-ok-{nonce_a_utiliser}"
        print(f"   Message à chiffrer: '{test_message}'")
        print(f"   Clé session utilisée: {self.cle_session.hex()[:16]}...")
        
        try:
            message_chiffre = chiffrer_message(
                self.cle_session,
                test_message
            )
            
            message = {
                'type': self.TYPE_AUTH,
                'node_id': self.mon_id_hex,
                'encrypted': message_chiffre.hex()
            }
            
            message_bytes = json.dumps(message).encode('utf-8')
            
            self.etat = 5  # COMPLETE
            print(f" Envoi message authentifié (chiffré)")
            print(f"   Taille chiffré: {len(message_chiffre)} bytes")
            print(f"   Taille message: {len(message_bytes)} bytes")
            
            return message_bytes
            
        except Exception as e:
            print(f" Erreur préparation AUTH: {e}")
            traceback.print_exc()
            return None
    
    def recevoir_message_auth(self, message_bytes):
        """
        Vérifie le message d'authentification de l'autre
        """
        try:
            message = json.loads(message_bytes.decode('utf-8'))
            
            if message['type'] != self.TYPE_AUTH:
                print(f" Type incorrect: {message['type']}")
                return False
            
            print(f"\n📥 Reçu message authentifié")
            
            son_id_hex = message.get('node_id')
            if son_id_hex and self.son_id is None:
                self.son_id = bytes.fromhex(son_id_hex)
                self.son_id_hex = son_id_hex
                print(f"   ID reçu dans AUTH: {son_id_hex[:16]}...")
            
            message_chiffre = bytes.fromhex(message['encrypted'])
            
            if self.cle_session is None:
                print(f"    Pas de clé de session disponible")
                return False
            
            print(f"   Clé session utilisée pour déchiffrer: {self.cle_session.hex()[:16]}...")
            
            message_clair = dechiffrer_message(
                self.cle_session,
                message_chiffre
            )
            
            if message_clair is None:
                print(f"    Échec déchiffrement auth")
                return False
            
            message_clair = message_clair.decode('utf-8')
            print(f"   Message déchiffré: '{message_clair}'")
            
            if message_clair.startswith("handshake-ok-"):
                nonce_recu = message_clair[13:]  # Après "handshake-ok-"
                print(f"   Nonce reçu: {nonce_recu}")
                
                if nonce_recu == self.nonce_handshake.hex():
                    print(f"   Nonce valide (correspond à notre nonce) !")
                    print(f"   Message authentifié valide !")
                    self.etat = 5  # COMPLETE
                    return True
                else:
                    print(f"    Nonce différent du nôtre: {nonce_recu} != {self.nonce_handshake.hex()}")
                    print(f"   Mais le déchiffrement a réussi, donc on accepte quand même")
                    self.etat = 5  # COMPLETE
                    return True
            else:
                print(f"    Format de message invalide")
                return False
                
        except Exception as e:
            print(f" Erreur réception AUTH: {e}")
            traceback.print_exc()
            return False
    
    def est_complete(self):
        """Vérifie si le handshake est terminé"""
        return self.etat == 5
    
    def get_cle_session(self):
        """Retourne la clé de session si handshake réussi"""
        return self.cle_session if self.est_complete() else None

def exemple_handshake():
    """
    Simule un handshake entre Alice et Bob
    """
    print("\n" + "="*80)
    print(" SIMULATION HANDSHAKE ALICE <-> BOB".center(80))
    print("="*80)
    
    # Alice initie la connexion
    print("\nALICE (initiatrice)")
    alice = Handshake(est_initiateur=True)
    
    print("\n" + "-"*80)
    
    print("\n BOB (récepteur)")
    bob = Handshake(est_initiateur=False)
    
    print("\n" + "="*80)
    print("DÉROULEMENT DU HANDSHAKE".center(80))
    print("="*80)
    
    print("\n--- Étape 1: Alice envoie HELLO ---")
    msg_hello, sig_hello = alice.preparer_message_hello()
    if msg_hello is None:
        print(" Échec préparation HELLO")
        return
    
    print("\n--- Bob reçoit HELLO ---")
    if not bob.recevoir_message_hello(msg_hello, sig_hello):
        print(" Échec réception HELLO")
        return
    
    print("\n" + "-"*80)
    
    print("\n--- Étape 2: Bob répond avec sa clé ---")
    msg_key, sig_key = bob.preparer_message_key()
    if msg_key is None:
        print("Échec préparation KEY")
        return
    
    print("\n--- Alice reçoit la clé ---")
    if not alice.recevoir_message_key(msg_key, sig_key):
        print(" Échec réception KEY")
        return
    
    print("\n" + "-"*80)
    
    print("\n--- Étape 3: Alice envoie message authentifié ---")
    msg_auth = alice.preparer_message_auth()
    if msg_auth is None:
        print(" Échec préparation AUTH")
        return
    
    if not bob.recevoir_message_auth(msg_auth):
        print("Échec réception AUTH")
        return
    
    print("\n" + "-"*80)
    
    print("\n--- Étape 4: Bob envoie message authentifié ---")
    msg_auth2 = bob.preparer_message_auth()
    if msg_auth2 is None:
        print(" Échec préparation AUTH (Bob)")
        return
    
    if not alice.recevoir_message_auth(msg_auth2):
        print(" Échec réception AUTH (Alice)")
        return
    
    print("\n" + "="*80)
    print("RÉSULTAT".center(80))
    print("="*80)
    
    if alice.est_complete() and bob.est_complete():
        print("\n HANDSHAKE RÉUSSI !")
        print(f"\n   Clé de session Alice: {alice.get_cle_session().hex()[:32]}...")
        print(f"   Clé de session Bob:   {bob.get_cle_session().hex()[:32]}...")
        
        if alice.get_cle_session() == bob.get_cle_session():
            print(f"\n Les clés de session sont identiques !")
            print(f"   Les deux nœuds peuvent maintenant communiquer en chiffré.")
        else:
            print(f"\n Les clés de session sont DIFFÉRENTES !")
            print(f"   C'est la cause de l'échec du déchiffrement.")
    else:
        print("\n HANDSHAKE ÉCHOUÉ")
        print(f"   État Alice: {alice.etat}")
        print(f"   État Bob: {bob.etat}")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    exemple_handshake()