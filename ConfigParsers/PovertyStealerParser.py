from Utils.PatternScanner import PScanner


def PovertyStealerConfigParser(Filename):

    # Grab Config Details from malware

    Pattern = r"c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??c645??8d8514fe"
    Offset, Result = PScanner(Filename, Pattern)

    for Bytes in Result:
        HexByte = [Bytes[i:i + 8] for i in range(0, len(Bytes), 8)] # Sort Bytes into 8 Bit representation per array

        try:
            OutArray = []
            for item in HexByte:
                AddressBytes = item[6:]
                OutArray.append(bytearray.fromhex(AddressBytes).decode())
        except:
            print(f"Unable to Parse {Filename}")

        JsonConfig = {
            "Exename": Filename,
            "C2 Address": "".join(OutArray[:len(OutArray) - 1])
        }

        return JsonConfig


