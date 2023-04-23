from argparse import ArgumentParser
from logging import basicConfig, DEBUG, WARNING

from RedLine.RedlineParser import RedLineParser
from XWorm.XwormParser import XWormParser
from Remcos.RemcosParser import retrieveResource

from Utils.ConfigList import list_configs

if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument(
        'File_Path',
        nargs='+',
        help=f'Sample you want Check'
    )
    ap.add_argument(
        '-d',
        '--debug',
        help='Enables Debugging mode'
    )
    ap.add_argument(
        '-m',
        '--mode',
        help='Choose what Family you want to retrieve configs from'
    )
    ap.add_argument(
        '-l',
        '--list',
        help='Shows a list of parsed configs',
        action='store_const',
        const=list_configs()
    )
    args = ap.parse_args()
    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)


    for fp in args.File_Path:
        try:
            if args.mode == 'RedLine':
                print("Redline Mode")
            else:
                print(f'No Family found for {fp}')
        except:
            print(f'Error Occurred while parsing {fp}')




