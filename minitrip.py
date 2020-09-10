""" Minitrip, a filesystem integrity check tool """

from pathlib import Path
from hashlib import sha256


def walk_paths(path):
    path = Path(path) if isinstance(path, str) else path
    for item in path.iterdir():
        if item.is_dir():
            yield from walk_paths(item)
        elif item.is_file():
            yield item


def hash(path):
    hash = sha256()

    with open(path,'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(4096)
            hash.update(chunk)

    return hash.digest()


def main():
    """ The main function for the `minitrip` command """
    for item in walk_paths("/home/wolf"):
        print(item)
        print(hash(item))


if __name__ == "__main__":
    main()
