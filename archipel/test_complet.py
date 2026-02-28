import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from src.crypto.hash import sha256_chunk
from src.crypto.keys import generer_cles
from src.node import get_node_id_hex

print("="*50)
print("TEST DE L'ENVIRONNEMENT PROPRE")
print("="*50)

# Test hash
h = sha256_chunk(b"test")
print(f"Hash: {h}")

# Test clés
cles = generer_cles()
print(f"Clés générées: OK")

print("="*50)
print(" TOUT FONCTIONNE !")
print("="*50)