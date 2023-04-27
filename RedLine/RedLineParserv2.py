from Utils.DotnetParser import ClrParser
from Utils.Ciphers.Xor import XorAlgorithm
from base64 import b64decode


def RedLineConfigParser(file_path):
    byte_config = b'(\x72.{9}){4}'
    result = ClrParser(file_path, byte_config)
    return Decrypt_Address(result.decrypted_config())


def Decrypt_Address(results):
    ''''Redline stealer uses Base64 -> XOR -> Base64 to string encrypt the address argument'''
    key = list(results.values())[-1]
    encrypted_id = list(results.values())[0]
    decrypted_id = decode64(encrypted_id)
    address = XorAlgorithm(key, decrypted_id)
    result = {
        'Address': b64decode(address).decode(),
        'ID': list(results.values())[1],
        'Message': list(results.values())[2],
        'Key': list(results.values())[3]
    }
    return result

def decode64(encoded_item):
    try:
        return b64decode(encoded_item)
    except:
        return encoded_item