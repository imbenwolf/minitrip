""" Minitrip, a filesystem integrity check tool """
import click
import plyvel
import sys
from os import environ
from time import time

from hash import hash
from scan import walk_paths

DEFAULT_DB_PATH = "$HOME/.minitripdb"


def add(db, file_path, label, verbose):
    db.put(hash(file_path), label)
    if verbose:
        sys.stderr.write(
            'New entry: "' + str(file_path) + '" with label "' + label.decode("utf-8") + '"\n')


def check(timestamp, hash_value, file_path):
    if timestamp is None or hash_value is not None and int(hash_value) < int(timestamp):
        if hash_value is None:
            sys.stdout.write(
                'File never seen before: "' + str(file_path) + '"\n')
        else:
            sys.stderr.write(
                'Malware found: "' + str(file_path) + '"\n')


def update(db, hash_value, file_path, verbose):
    if hash_value is None:
        db.put(hash(file_path), bytes(str(int(time())), "utf-8"))
    elif verbose and hash_value.decode("utf-8").isdigit():
        sys.stderr.write('Found file "' + str(file_path) +
                         '" with value "' + hash_value.decode("utf-8") + '"\n')


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('PATH', type=click.Path(exists=True), nargs=-1)
@click.option('-v', '--verbose', is_flag=True, type=bool)
@click.option('-d', '--database', default=DEFAULT_DB_PATH, show_default=True, help="database path")
@click.option('-a', '--add', 'mode', flag_value='a', is_flag=True, help="Run in add mode (add malware samples)")
@click.option('-u', '--update', 'mode', flag_value='u', is_flag=True, help="Run in update mode (record timestamps for new files)")
@click.option('-t', '--timestamp', type=int, help="For check mode, ignore all hashes whose timestamp is newer than the desired time")
@click.option('-l', '--label', help="For add mode, set an explicit label instead of the filename stem")
def main(verbose, database, mode, timestamp, label, path):
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
        for file_path in walk_paths(path):
            label_db = bytes(
                file_path.stem if label is None else label, "utf-8")
            hash_value = db.get(hash(file_path))

            if mode == 'a':
                if hash_value is None:
                    add(db, file_path, label_db, verbose)

            elif mode == 'c':
                check(timestamp, hash_value, file_path)

            elif mode == 'u':
                update(db, hash_value, file_path, verbose)

    db.close()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
