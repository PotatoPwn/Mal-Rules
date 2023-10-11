from re import compile

def PScanner(Filename, Pattern):
    with open(Filename, "rb") as File:
        BinaryData = File.read()
        File.close()

    # Replace ? with .. in pattern for pattern matcher
    CleanPattern = str(Pattern).replace("?", r"..")
    Regex = compile(CleanPattern)

    Matches = [(match.start(), match.group(0)) for match in Regex.finditer(BinaryData.hex())]

    # Returns Offset, Result
    return Matches
