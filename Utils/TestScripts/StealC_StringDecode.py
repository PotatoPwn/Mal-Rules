from base64 import b64decode


EncodedContent = [
    (0x6181dc, "i5nOa+jsEsnINmOOWTw="),
    (0x618358, "3ZLJIajqFI6CKjg=")
]

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

    return bytes(ciphertext)

def rc4_decrypt(ciphertext, key):

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

    return bytes(plaintext)

if __name__ == '__main__':
    key = "7696828025218469013746907565"
    keybytes = bytes(key, 'utf-8')
    for address, item in EncodedContent:
        result = rc4_decrypt(b64decode(item), keybytes)
        print(result.decode("utf-8"))
        print(hex(address))




#>>> mysym = Symbol(SymbolType.FunctionSymbol, 0x6182a4, "test") 
#>>> bv.define_user_symbol(mysym)