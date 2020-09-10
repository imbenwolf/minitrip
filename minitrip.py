""" Minitrip, a filesystem integrity check tool """

from pathlib import Path

def walk_paths(path):
    path = Path(path) if isinstance(path, str) else path
    for item in path.iterdir():
        if item.is_dir():
            yield from walk_paths(item)
        else:
            yield item


def main():
    """ The main function for the `minitrip` command """
    for item in walk_paths("/home/wolf"):
        print(item)


if __name__ == "__main__":
    main()
