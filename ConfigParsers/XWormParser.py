from Utils.DotnetParser import ClrParser
from hashlib import md5
from base64 import b64decode
from Crypto.Cipher import AES
from re import sub


def XWormConfigParser(file_path):
    byte_config = b'(\x72.{9}){3}'
    rva_pattern = b'\x72(.{4})\x80(.{4})'
    enc_result = ClrParser(file_path, byte_config, rva_pattern)

    DecryptedResult = enc_result.decrypted_config()

    key = generate_aes_key(list(DecryptedResult.values())[-1])
    host = decode_rest(list(DecryptedResult.values())[0], key)
    port = decode_rest(list(DecryptedResult.values())[1], key)

    JsonConfig = {
        "Exe Name": file_path,
        'Host': host[:-3],
        'Port': sub(r"\f", "", port),
        'Key': key
    }

    return JsonConfig


def generate_aes_key(mutex):
    '''This malware Converts its mutex into an md5 hash and adds onto it twice...'''
    m_hash = md5(bytes(mutex, 'UTF-8')).hexdigest()
    key = m_hash[:30] + m_hash + '00'
    return key


def decode_rest(enc_text, key):
    init_key = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    stage_1 = b64decode(enc_text)
    stage_2 = init_key.decrypt(stage_1).decode()
    return stage_2
