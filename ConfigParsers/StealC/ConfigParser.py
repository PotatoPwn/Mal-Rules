from base64 import b64decode

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


def FindData(offset, filename):
	with open(filename, "rb") as file:
		file.seek(offset, 1)
		Key = file.read(28)
		Data = file.read()

		file.close()
		return Key, Data


def find_base64(data):
	base64_strings = []

	segments = data.split(b'\x00')

	for chunk in segments:
		try:
			decoded_dat = b64decode(chunk)
			base64_strings.append(chunk.decode("utf-8"))
		except:
			pass

	return base64_strings

# todo Needs testing
def StealCParse(FileName):
	ConfigOffset = 0x1409c

	# Retrieve the Key & Data
	Key, Data = FindData(ConfigOffset, FileName)

	base64_strings = find_base64(Data)
	filtereditem = [item for item in base64_strings if item != '']


	# Decode Items
	Decoded_Strings = []

	for item in filtereditem:
		try:
			Result = rc4_decrypt(b64decode(item), Key)
			Decoded_Strings.append(Result.decode("utf-8"))
		except:
			pass

	Clean_Results = {
	"C2 Hostname": Decoded_Strings[42],
	"SubDomain": Decoded_Strings[43],
	"Endpoint": Decoded_Strings[44]

	}
	return Clean_Results
	
