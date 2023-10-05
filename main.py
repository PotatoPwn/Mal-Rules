#!/usr/bin/env python3

from os import listdir
from os.path import isfile, join

from argparse import ArgumentParser
from logging import basicConfig, DEBUG, WARNING

import yara

from ConfigParsers.RedLineParser import RedLineConfigParser
from ConfigParsers.XWormParser import XWormConfigParser
from ConfigParsers.RemcosParser import RemcosConfigParser
from ConfigParsers.NJRatParser import NJRatConfigParser
from ConfigParsers.StealCParser import StealCConfigParser
from ConfigParsers.LokiBotParser import LokiBotConfigParser

from Utils.ConfigList import ListConfigs


def DecryptConfig(FileName, FamilySample):
    _FamilyName = FamilySample.lower()

    try:
        match _FamilyName:
            case "redline":
                PResults = RedLineConfigParser(FileName)
            case "xworm":
                PResults = XWormConfigParser(FileName)
            case "remcos":
                PResults = RemcosConfigParser(FileName)
            case "njrat":
                PResults = NJRatConfigParser(FileName)
            case "stealc":
                PResults = StealCConfigParser(FileName)
            case "lokiBot":
                PResults = LokiBotConfigParser(FileName)
            case _:
                print(f"No config found for {FileName}")
                return

        print(PResults)
    except:
        print(f"Error Parsing {FileName}")


if __name__ == '__main__':
    ListConfigs()

    ap = ArgumentParser()

    ap.add_argument('-f', '--path', help='Folder Sample You wish to Check')

    ap.add_argument('-d', '--debug', help='Enables Debugging mode')

    ap.add_argument('-m', '--mode', help='Choose what Family you want to retrieve configs from')

    args = ap.parse_args()
    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)

    # Get Files
    if args.path is None:
        Directory = "SampleFolder"
    else:
        Directory = args.path

    YaraRules = [file for file in listdir("YaraRules") if isfile(join("YaraRules", file))]

    try:
        Samples = [file for file in listdir(Directory) if isfile(join(Directory, file))]
    except:
        print(f"{Directory} Doesnt Exist, Exiting...")
        exit(1)

    for Malware in Samples:
        for Rules in YaraRules:
            _SamplePath = f"{Directory}/{Malware}"
            _YaraRules = f"YaraRules/{Rules}"

            YarRule = yara.compile(_YaraRules)
            Matches = YarRule.match(_SamplePath)

            if Matches:
                print(f"The sample {Malware}, Matches with the rule {Rules}")
                DecryptConfig(_SamplePath, _YaraRules)
