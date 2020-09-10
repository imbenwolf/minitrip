from pathlib import Path

def walk_paths(path):
    path = Path(path) if isinstance(path, str) else path
    for item in path.iterdir():
        if item.is_dir():
            yield from walk_paths(item)
        elif item.is_file():
            yield item