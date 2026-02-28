import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from crypto.keys import generer_cles, cle_en_hex
from crypto.storage import sauvegarder_cles, charger_cles, DOSSIER_ARCHIPEL

def get_ou_creer_identite():
    """Charge ou crée l'identité"""
    print("\n ARCHIPEL - Initialisation de l'identité")
    print("=" * 50)
    
    cles = charger_cles()
    
    if cles:
        print(" Identité existante chargée !")
    else:
        print(" Première utilisation - Création...")
        cles = generer_cles()
        sauvegarder_cles(cles)
        print(" Nouvelle identité créée !")
    
    id_hex = cle_en_hex(cles['publique'])
    print(f"\n Identité du nœud :")
    print(f"   ID: {id_hex[:16]}...{id_hex[-16:]}")
    print(f"   Fichier: {DOSSIER_ARCHIPEL}/identity.json")
    print("=" * 50)
    
    return cles

if __name__ == "__main__":
    get_ou_creer_identite()