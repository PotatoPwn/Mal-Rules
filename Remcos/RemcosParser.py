from pefile import PE
from arc4 import ARC4
from json import dumps

from argparse import ArgumentParser

def retrieveResource(filename):
    pe = PE(filename)
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size

    data = pe.get_data(offset,size)
    return data

def decrypt_info(data):
    key_len_byte = data[0]
    key_len = key_len_byte
    key = data[1:key_len+1]
    encrypted_data = data[key_len+1:]
    key_init = ARC4(key)
    info = key_init.decrypt(encrypted_data)
    cleaned = info.decode().replace("@", "")
    return cleaned


if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument(
        'file_paths',
        nargs='+',
        help=f'One of more deobfuscated remcos parser'
    )
    args = ap.parse_args()
    config = []
    for fp in args.file_paths:
        try:
            config.append(f'Binary: {fp} Configuration: {(decrypt_info(retrieveResource(fp)))}')
        except:
            print(f'Error has occured for {fp}')
            continue
    if len(fp) > 0:
        print(dumps(config))