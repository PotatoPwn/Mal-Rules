# Rc4 Encryption & Decryption without Library
# https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071
# https://en.wikipedia.org/wiki/RC4

def rc4_encrypt(plaintext, key):
    # Format Text
    enckey = bytes(key, 'utf-8')
    encplaintext = bytes(plaintext, 'utf-8')
    # Initialize S-box
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + enckey[i % len(enckey)]) % 256
        S[i], S[j] = S[j], S[i]

    # Generate keystream and encrypt plaintext
    i = j = 0
    ciphertext = []
    for byte in encplaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        ciphertext.append(byte ^ k)

    print(enckey.hex())
    return bytes(ciphertext).hex()

def rc4_decrypt(ciphertext, key):
    # Format Text
    key = bytes(key, 'utf-8')
    ciphertext = bytes(ciphertext, 'utf-8')

    # Initialize S-box
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Generate keystream and decrypt ciphertext
    i = j = 0
    plaintext = []
    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plaintext.append(byte ^ k)

    return bytes(plaintext).hex()
