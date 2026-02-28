# src/crypto/manifest.py
"""
Gestion des manifests de fichiers (signés)
"""
import sys
import os

# Ajoute le chemin pour les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import json
import math
import time
from crypto.hash import sha256_fichier, sha256_chunk
from node import signer, verifier, get_node_id_hex

class Manifest:
    def __init__(self, chemin_fichier=None, chunk_size=524288):  # 512 KB par défaut
        """
        Crée ou charge un manifest
        
        Args:
            chemin_fichier: Chemin vers le fichier à partager
            chunk_size: Taille des chunks en bytes
        """
        self.chunk_size = chunk_size
        self.data = None
        
        if chemin_fichier:
            self.creer_depuis_fichier(chemin_fichier)
    
    def creer_depuis_fichier(self, chemin_fichier):
        """
        Crée un manifest pour un fichier
        """
        print(f"📋 Création du manifest pour {chemin_fichier}")
        
        # Vérifie que le fichier existe
        if not os.path.exists(chemin_fichier):
            raise FileNotFoundError(f"Fichier {chemin_fichier} introuvable")
        
        # Taille du fichier
        taille = os.path.getsize(chemin_fichier)
        nb_chunks = math.ceil(taille / self.chunk_size)
        
        print(f"   Taille: {taille} bytes")
        print(f"   Chunks: {nb_chunks} de {self.chunk_size} bytes")
        
        # Calcul du hash du fichier complet
        file_hash = sha256_fichier(chemin_fichier)
        print(f"   SHA-256 fichier: {file_hash[:16]}...")
        
        # Création de la liste des chunks
        chunks = []
        with open(chemin_fichier, 'rb') as f:
            for i in range(nb_chunks):
                # Lire le chunk
                chunk_data = f.read(self.chunk_size)
                
                # Calculer son hash
                chunk_hash = sha256_chunk(chunk_data)
                
                chunks.append({
                    'index': i,
                    'hash': chunk_hash,
                    'size': len(chunk_data)
                })
                
                if i % 10 == 0:
                    print(f"   Chunk {i}/{nb_chunks} traité...")
        
        # Construction du manifest
        self.data = {
            'file_id': file_hash,
            'filename': os.path.basename(chemin_fichier),
            'size': taille,
            'chunk_size': self.chunk_size,
            'nb_chunks': nb_chunks,
            'chunks': chunks,
            'sender_id': get_node_id_hex(),
            'timestamp': str(int(time.time()))
        }
        
        print(f"✅ Manifest créé avec {nb_chunks} chunks")
    
    def signer(self):
        """
        Signe le manifest avec la clé privée du nœud
        """
        if not self.data:
            raise ValueError("Pas de manifest à signer")
        
        # Convertir en bytes pour la signature (sort_keys pour être déterministe)
        manifest_bytes = json.dumps(self.data, sort_keys=True).encode('utf-8')
        
        # Signer
        signature = signer(manifest_bytes)
        
        # Ajouter la signature
        self.data['signature'] = signature.hex()
        
        print(f"🔏 Manifest signé")
        return self.data
    
    def verifier_signature(self):
        """
        Vérifie la signature du manifest
        """
        if not self.data or 'signature' not in self.data:
            print("❌ Pas de signature dans le manifest")
            return False
        
        # Récupérer l'ID de l'émetteur
        sender_id_hex = self.data.get('sender_id')
        if not sender_id_hex:
            print("❌ Pas de sender_id dans le manifest")
            return False
        
        sender_id = bytes.fromhex(sender_id_hex)
        signature = bytes.fromhex(self.data['signature'])
        
        # Enlever la signature pour vérifier
        data_sans_sig = self.data.copy()
        del data_sans_sig['signature']
        
        manifest_bytes = json.dumps(data_sans_sig, sort_keys=True).encode('utf-8')
        
        # Vérifier
        if verifier(sender_id, manifest_bytes, signature):
            print(f"✅ Signature du manifest valide")
            return True
        else:
            print(f"❌ Signature du manifest invalide !")
            return False
    
    def sauvegarder(self, chemin):
        """
        Sauvegarde le manifest dans un fichier
        """
        if not self.data:
            raise ValueError("Pas de manifest à sauvegarder")
        
        with open(chemin, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Manifest sauvegardé dans {chemin}")
    
    def charger(self, chemin):
        """
        Charge un manifest depuis un fichier
        """
        with open(chemin, 'r', encoding='utf-8') as f:
            self.data = json.load(f)
        
        print(f"📂 Manifest chargé: {self.data['filename']}")
        return self.data

# Test si exécuté directement
if __name__ == "__main__":
    print("Test de manifest.py")
    # Crée un petit fichier de test
    with open("test_manifest.txt", "w") as f:
        f.write("A" * 1024)  # 1KB
    
    m = Manifest("test_manifest.txt")
    m.signer()
    m.verifier_signature()
    
    os.remove("test_manifest.txt")
    print("Test terminé")