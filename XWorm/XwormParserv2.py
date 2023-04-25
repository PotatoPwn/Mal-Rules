from Utils.DotnetParser import ClrParser

def XWormConfigParser(file_path):
    byte_config = b'(\x72.{9}){3}'
    Result = ClrParser(file_path, byte_config)
    print(Result.decrypted_config())