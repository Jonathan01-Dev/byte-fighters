import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import json
from pathlib import Path

DOSSIER_ARCHIPEL = Path.home() / '.archipel'
FICHIER_CLE = DOSSIER_ARCHIPEL / 'identity.json'

def sauvegarder_cles(cles):
    """
    Sauvegarde les clés dans ~/.archipel/identity.json
    """
    DOSSIER_ARCHIPEL.mkdir(exist_ok=True)
    
    donnees = {
        'publique': cles['publique'].hex(),
        'privee': cles['privee'].hex()
    }
    
    with open(FICHIER_CLE, 'w') as f:
        json.dump(donnees, f, indent=2)
    
    print(f" Clés sauvegardées dans {FICHIER_CLE}")
    return True

def charger_cles():
    """
    Charge les clés depuis le disque
    """
    if not FICHIER_CLE.exists():
        return None
    
    try:
        with open(FICHIER_CLE, 'r') as f:
            donnees = json.load(f)
        
        return {
            'publique': bytes.fromhex(donnees['publique']),
            'privee': bytes.fromhex(donnees['privee'])
        }
    except Exception as e:
        print(f"Erreur lors du chargement: {e}")
        return None
    