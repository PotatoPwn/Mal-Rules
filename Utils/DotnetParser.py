from logging import getLogger

logger = getLogger(__name__)

class ErrorHandling(Exception):
    pass

class ClrParser:

    # Static Dotnet Configs
    RET_OPCODE = b'\x2a'
    PATTERN_CLR_METADATA_START = b'\x42\x53\x4a\x42'
    #PATTERN_CONFIG_START = config_pattern todo instead of calling this constant, have it use the variable instead
    PATTERN_PARSED_RVAS = b'\x72(.{4})\x80(.{4})'
    STREAM_IDENTIFIER_STORAGE = b'#~'
    STREAM_IDENTIFIER_STRINGS = b'#Strings'
    STREAM_IDENTIFIER_US = b'#US'
    TABLE_FIELD = 'Field'
    RVA_US_BASE = 0x70000000
    RVA_STRING_BASE = 0x04000000

    # Error Handling


    def __init__(self, file_path, config_pattern_bytes):
        self.config_pattern = config_pattern_bytes
        self.file_path = file_path
        self.file_data = self.retrieve_file_data()

    def retrieve_file_data(self):
        logger.debug(
            f'Reading Contents Of: {self.file_path}'
        )
        try:
            with open(self.file_path, 'rb') as fp:
                data = fp.read()
        except Exception as e:
            raise ErrorHandling(
                f'Error while attempting to read {self.file_path}'
            ) from e
        return data

    def get_fields_map(self):
        pass



