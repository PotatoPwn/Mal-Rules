from pefile import PE
from Utils.Algorithms.Rc4 import rc4_decrypt
from re import search, sub
from string import printable


def RemcosConfigParser(file_path):
    try:
        data_section = retrieve_correct_section(file_path)
        decrypted_data = decrypt_info(data_section)
        return identify_config(decrypted_data)
    except Exception:
        return f'Error for {file_path} has occurred'


def retrieve_correct_section(file_path):
    pe = PE(file_path)
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
    data = pe.get_data(offset, size)
    return data

def decrypt_info(data):
    '''
    The malware uses the first byte to identify how long the key will be
    Everything after the key is to be decrypted
    '''
    key_len_id = data[0]
    key = data[1:key_len_id+1]
    encrypted_data = data[key_len_id+1:]
    decrypted_data = rc4_decrypt(encrypted_data, key)
    return (decrypted_data)

def retrieve_c2(data):
    parsed_strings = []
    while ":1" in data:
        result = search("^(.*):1", data)
        if result:
            parsed_string = result.group(1)
            parsed_strings.append(parsed_string)
            data = data.replace(parsed_string + ":1", "")
        else:
            break
    return parsed_string

def identify_rest(decoded_data, strlength):
    addressless_config = decoded_data[strlength+2:]
    array = addressless_config.split('|')
    cleaned_list = [c for c in array if c.isprintable()]
    return cleaned_list

def identify_config(data):
    decoded_data = data.decode("utf-8", "ignore")
    c2 = retrieve_c2(decoded_data)
    cleaned_c2 = c2.split(':1')
    config_items = identify_rest(decoded_data, len(c2))
    results = {
        "C2 Addresses": cleaned_c2,
        "BOTNET ID": config_items[0],
        "Mutex": config_items[6],
        "Screenshot Folder": config_items[12],
        "Recording Folder": config_items[14]
    }
    return results