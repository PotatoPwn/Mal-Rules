from Utils.DotnetParser import ClrParser

def RedLineConfigParser(file_path):
    byte_config = b'(\x72.{9}){4}'
    Result = ClrParser(file_path, byte_config)
    print(Result.decrypted_config())
