from itertools import cycle

def XorAlgorithm(key: str, data_bytes: bytes):
    '''Function for decrypting Xor Algorithms'''
    key_byte = bytes(key, 'utf-8')
    xorAlgorithm = ''.join(chr(x ^ y) for (x,y) in zip(data_bytes, cycle(key_byte)))
    return xorAlgorithm

