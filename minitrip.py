""" Minitrip, a filesystem integrity check tool """
import click

from hash import hash
from scan import walk_paths

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('PATH', type=click.Path(exists=True), nargs=-1)
@click.option('-v', '--verbose', is_flag=True)
@click.option('-d', '--database', default="$HOME/.minitripdb", show_default=True, help="database path")
@click.option('-a', '--add', 'mode', flag_value='u', is_flag=True, help="Run in add mode (add malware samples)", default='c')
@click.option('-u', '--update', 'mode', flag_value='a', is_flag=True, help="Run in update mode (record timestamps for new files)", default='c')
@click.option('-l', '--label', help="For add mode, set an explicit label instead of the filename stem")
def main(verbose, database, mode, label, path):
    """ Tool to lookup known file hashes """
    path = set(path)
    if len(path) == 0:
        path.add(".")

    for path in path: 
        for item in walk_paths(path):
            print(item)
            print(hash(item))


if __name__ == "__main__":
    main() # pylint: disable=no-value-for-parameter
