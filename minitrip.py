""" Minitrip, a filesystem integrity check tool """
import click
import plyvel
from os import environ
from time import time

from hash import hash
from scan import walk_paths

DEFAULT_DB_PATH = "$HOME/.minitripdb"

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('PATH', type=click.Path(exists=True), nargs=-1)
@click.option('-v', '--verbose', is_flag=True)
@click.option('-d', '--database', default=DEFAULT_DB_PATH, show_default=True, help="database path")
@click.option('-a', '--add', 'mode', flag_value='a', is_flag=True, help="Run in add mode (add malware samples)")
@click.option('-u', '--update', 'mode', flag_value='u', is_flag=True, help="Run in update mode (record timestamps for new files)")
@click.option('-l', '--label', help="For add mode, set an explicit label instead of the filename stem")
def main(verbose, database, mode, label, path):
    """ Tool to lookup known file hashes """
    mode = 'c' if mode is None else mode

    if database == DEFAULT_DB_PATH:
        database_folder = database.split("/").pop()
        database = environ['HOME'] + "/" + database_folder

    db = plyvel.DB(database, create_if_missing=True)

    path = set(path)
    if len(path) == 0:
        path.add(".")

    for path in path: 
        for item in walk_paths(path):
            label_db = bytes(item.stem if label is None else label, "utf-8")

            if mode == 'a':
                db.put(hash(item), label_db)
            elif mode == 'c' or mode == 'u':
                hash_db = db.get(hash(item))
                
                if mode == 'c':
                    print("File never seen before" if hash_db is None else "Malware found")
                elif mode == 'u':
                    db.put(hash(item), bytes(str(int(time())), "utf-8"))

    db.close()


if __name__ == "__main__":
    main() # pylint: disable=no-value-for-parameter
