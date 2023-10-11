from base64 import b64decode

from Utils.Ciphers.Xor import XorAlgorithm
from Utils.DotnetParser import ClrParser


def RedLineConfigParser(file_path):
    ByteConfig = b'(\x72.{9}){4}'
    RVAPattern = b'\x72(.{4})\x80(.{4})'
    Result = ClrParser(file_path, ByteConfig, RVAPattern)
    return Decrypt_Address(Result.decrypted_config())


def Decrypt_Address(results):
    ''''Redline stealer uses Base64 -> XOR -> Base64 to string encrypt the address argument'''
    Key = list(results.values())[-1]
    EncryptedID = list(results.values())[0]
    DecryptedID = decode64(EncryptedID)
    Address = XorAlgorithm(Key, DecryptedID)
    result = {
        'Address': b64decode(Address).decode(),
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
