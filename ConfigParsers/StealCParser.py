from base64 import b64decode

from Utils.Algorithms.Rc4 import rc4_decrypt


def FindData(offset, filename):
    with open(filename, "rb") as file:
        file.seek(offset, 1)
        Key = file.read(28)
        Data = file.read()

        file.close()
        return Key, Data


def find_base64(data):
    Base64String = []

    segments = data.split(b'\x00')

    for chunk in segments:
        try:
            decoded_dat = b64decode(chunk)
            Base64String.append(chunk.decode("utf-8"))
        except:
            pass

    return Base64String


# todo Needs testing
def StealCConfigParser(FileName):
    ConfigOffset = 0x1409c

    # Retrieve the Key & Data
    Key, Data = FindData(ConfigOffset, FileName)

    Base64String = find_base64(Data)
    FilteredItems = [item for item in Base64String if item != '']

    # Decode Items
    DecodedStrings = []

    for item in FilteredItems:
        try:
            Result = rc4_decrypt(b64decode(item), Key)
            DecodedStrings.append(Result.decode("utf-8"))
        except:
            pass

    EndpointInformation = {
        "C2 Hostname": DecodedStrings[42],
        "SubDomain": DecodedStrings[43],
        "Endpoint": DecodedStrings[44]
    }

    DecryptedStrings = []
    for i in DecodedStrings:
        DecryptedStrings.append(i)

    JsonResult = {
        "Exe Name": FileName,
        "C2 Information": EndpointInformation,
        "Decoded Strings": DecryptedStrings
    }

    return JsonResult
