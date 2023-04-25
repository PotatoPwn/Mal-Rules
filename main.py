from argparse import ArgumentParser
from logging import basicConfig, DEBUG, WARNING

from RedLine.RedLineParserv2 import RedLineConfigParser
from XWorm.XwormParserv2 import XWormConfigParser
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
            if args.mode.lower() == "redline":
                RedLineConfigParser(fp)
            if args.mode.lower() == "xworm":
                XWormConfigParser(fp)
            else:
                print(f"No config for {args.mode}")
        except:
            print(f'Error Occurred while parsing {fp}')




