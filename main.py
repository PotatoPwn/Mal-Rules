#!/usr/bin/env python3

from argparse import ArgumentParser
from logging import basicConfig, DEBUG, WARNING
from json import dumps

from RedLine.RedLineParserv2 import RedLineConfigParser
from XWorm.XwormParserv2 import XWormConfigParser
from Remcos.RemcosParserv2 import RemcosConfigParser
from NJRat.NJRatParser import NJParser



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
        results = []
        try:
            if args.mode.lower() == "redline":
                parsed_results = RedLineConfigParser(fp)
            elif args.mode.lower() == "xworm":
                parsed_results = XWormConfigParser(fp)
            elif args.mode.lower() == "remcos":
                parsed_results = RemcosConfigParser(fp)
            elif args.mode.lower() == "njrat":
                parsed_results = NJParser(fp)
            else:
                print(f"No config for {args.mode}")
            results.append(parsed_results)
        except:
            print(f'Error Occurred while parsing {fp}')

    print(dumps(parsed_results, indent=2))





