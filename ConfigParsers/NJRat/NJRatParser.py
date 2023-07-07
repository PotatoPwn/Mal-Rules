from Utils.DotnetParser import ClrParser


def NJParser(file_path):
    byte_config = b'(\x20.{14})(\x72.{4})'
    rva_pattern = b'\x72(.{4})\x80(.{4})'
    parsed_config = ClrParser(file_path, byte_config, rva_pattern)
    config_info = list(parsed_config.decrypted_config().values())
    print(config_info)

    result = {
        'Dropper Directory': config_info[0],
        'Executable Name': config_info[1],
        'HostAddress': config_info[2]
    }
    return result