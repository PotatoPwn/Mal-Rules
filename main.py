#!/usr/bin/env python3

from argparse import ArgumentParser
from logging import basicConfig, DEBUG, WARNING
from json import dumps

from ConfigParsers.RedLine.RedLineParserv2 import RedLineConfigParser
from ConfigParsers.XWorm.XwormParserv2 import XWormConfigParser
from ConfigParsers.Remcos.RemcosParserv2 import RemcosConfigParser
from ConfigParsers.NJRat.NJRatParser import NJParser
from ConfigParsers.StealC.ConfigParser import StealCParse
from ConfigParsers.LokiBot.LokiExtractor import LokiBotConfigExtraction



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

    '''
    yara Python can only compile one rule at a time
    here is an example of what you could do
    
    for malware in sampledir:
        for yararule in ruledir:
            try:
                rule = compile(yararule)
                scanresult = rule.scan(malware)
                if scanresult != null
                    result.append(parseconfig(malware))
                else
                    continue
            except:
                print "scan rule failed for malware"
    
    '''


    for fp in args.File_Path:
        results = []
        # Use Case Statements here
        try:
            SampleName = args.mode.lower()

            match SampleName:
                case "redline":
                    PResults = RedLineConfigParser(fp)
                case "xworm":
                    PResults = XWormConfigParser(fp)
                case "remcos":
                    PResults = RemcosConfigParser(fp)
                case "njrat":
                    PResults = NJParser(fp)
                case "stealc":
                    PResults = StealCParse(fp)
                case "LokiBot":
                    PResults = LokiBotConfigExtraction(fp)
                case _:
                    print(f"No config found for {SampleName}")

            results.append(PResults)
        except:
            print(f'Error Occurred while parsing {fp}')

    print(dumps(PResults, indent=2))





