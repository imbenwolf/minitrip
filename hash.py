from hashlib import sha256

def hash(path):
    hash = sha256()

    with open(path, 'rb') as file:
        chunk = []
        while chunk != b'':
            chunk = file.read(4096)
            hash.update(chunk)

    return hash.digest()