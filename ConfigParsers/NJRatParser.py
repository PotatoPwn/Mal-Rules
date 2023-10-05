from Utils.DotnetParser import ClrParser


def NJRatConfigParser(FilePath):
    ByteConfig = b'(\x20.{14})(\x72.{4})'
    RVAPattern = b'\x72(.{4})\x80(.{4})'
    ParsedConfig = ClrParser(FilePath, ByteConfig, RVAPattern)
    ConfigInfo = list(ParsedConfig.decrypted_config().values())

    DecodedStrings = []

    for item in ConfigInfo:
        DecodedStrings.append(item)

    Result = {
        "Exe Name": FilePath,
        "C2 Address": ConfigInfo[2],
        "Decoded Strings": DecodedStrings
    }
    
    return Result