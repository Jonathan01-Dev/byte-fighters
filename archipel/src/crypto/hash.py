import hashlib

def sha256_chunk(data):
    """
    Calcule le SHA-256 d'un chunk de données
    """
    return hashlib.sha256(data).hexdigest()

def verifier_chunk(data, hash_attendu):
    """
    Vérifie qu'un chunk correspond à son hash
    """
    return sha256_chunk(data) == hash_attendu

def sha256_fichier(chemin):
    """
    Calcule le SHA-256 d'un fichier complet
    """
    sha256 = hashlib.sha256()
    with open(chemin, 'rb') as f:
        for bloc in iter(lambda: f.read(65536), b''):
            sha256.update(bloc)
    return sha256.hexdigest()