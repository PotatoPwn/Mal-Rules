from logging import getLogger
from re import DOTALL, findall, search
from MapTable import MAP_TABLE

logger = getLogger(__name__)

class ErrorHandling(Exception):
    pass

class ClrParser:

    # Static Dotnet Configs
    RET_OPCODE = b'\x2a'
    PATTERN_CLR_METADATA_START = b'\x42\x53\x4a\x42'
    PATTERN_PARSED_RVAS = b'\x72(.{4})\x80(.{4})'
    STREAM_IDENTIFIER_STORAGE = b'#~'
    STREAM_IDENTIFIER_STRINGS = b'#Strings'
    STREAM_IDENTIFIER_US = b'#US'
    TABLE_FIELD = 'Field'
    RVA_US_BASE = 0x70000000
    RVA_STRING_BASE = 0x04000000
    MAP_TABLE = MAP_TABLE

    # Error Handling


    def __init__(self, file_path, config_pattern_bytes):
        self.PATTERN_CONFIG_START = config_pattern_bytes
        self.file_path = file_path
        self.file_data = self.retrieve_file_data()
        self.table_map = self.get_table_map()
        self.fields_map = self.get_fields_map()
        self.config_addr_map = self.get_config_addr_map()
        self.translated_config = self.retrieve_translated_config()
        self.decrypted_strings = self.decrypted_config()


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

    def get_config_addr_map(self):
        logger.debug(
            f'Extracting Config Address Map for {self.file_path}'
        )
        config_mappings = []
        hit = search(self.PATTERN_CONFIG_START, self.file_data, DOTALL)
        if hit is None:
            raise ErrorHandling(
                f'Error Searching for Start of pattern for {self.file_path}'
            )
        config_start = hit.start()
        logger.debug(
            f'Found Config at {config_start}'
        )
        parsed_ops = self.get_string_from_offset(config_start, self.RET_OPCODE)
        parsed_rva = findall(self.PATTERN_PARSED_RVAS, parsed_ops, DOTALL)
        for (us_rva, string_rva) in parsed_rva:
            config_value_rva = self.bytes_to_int(us_rva)
            config_name_rva = self.bytes_to_int(string_rva)
            config_mappings.append((config_value_rva, config_name_rva))
        logger.debug(
            f'Found Config Item: ({hex(config_value_rva)}, {hex(config_name_rva)}'
        )
        return config_mappings


    def get_table_map(self):
        logger.debug(
            f'Extracting Table Map for {self.file_path}'
        )
        mask_valid = self.extract_mask_valid()
        table_map = self.MAP_TABLE.copy()
        storage_stream_offset = self.get_stream_start(self.STREAM_IDENTIFIER_STORAGE)
        table_start = storage_stream_offset + 24
        cur_offset = table_start
        try:
            for table in table_map:
                if mask_valid & (2**list(table_map.keys()).index(table)):
                    row_count_packed = self.file_data[cur_offset:cur_offset+4]
                    row_count = self.bytes_to_int(row_count_packed)
                    table_map[table]['num_rows'] = row_count
                    logger.debug(
                        f'Found {row_count} rows for table {table}'
                    )
                    cur_offset += 4
                else:
                    table_map[table]['num_row'] = 0
        except Exception as e:
            raise ErrorHandling(
                f'Unable to get counts of row from table'
            ) from e
        logger.debug(
            f'Successfully extracted Table Map'
        )
        return table_map

    def get_fields_map(self):
        logger.debug(
            f'Extracting Field Maps for {self.file_path}'
        )
        field_map = []
        fields_start = self.get_table_start(self.TABLE_FIELD)
        strings_start = self.get_stream_start(self.STREAM_IDENTIFIER_STRINGS)
        cur_offset = fields_start
        for x in range(self.table_map[self.TABLE_FIELD]['num_rows']):
            try:
                field_offset = self.bytes_to_int(self.file_data[cur_offset+2:
                                                                cur_offset+4])
                field_value = self.get_string_from_offset(strings_start+
                                                          field_offset)
                cur_offset += self.table_map[self.TABLE_FIELD]['row_size']
            except Exception as e:
                raise ErrorHandling(
                    f'Error while parsing field table'
                ) from e
            logger.debug(
                f'Successfully extracted fields map with the fields\n'
                f'{hex(field_offset)}, {field_value}'
            )
            field_map.append((field_value, field_offset))
        return field_map

    def get_table_start(self, table_name):
        storage_stream_offset = self.get_stream_start(self.STREAM_IDENTIFIER_STORAGE)
        table_start_offset = storage_stream_offset + 24 + (4 * len([
            table for table in self.table_map
            if self.table_map[table]['num_rows'] > 0
        ]))
        table_offset = table_start_offset
        for table in self.table_map:
            if table == table_name:
                break
            elif 'row_size' not in self.table_map[table]:
                raise ErrorHandling(
                    f'Invalid Table Offset Found'
                )
            table_offset += self.table_map[table]['row_size'] * self.table_map[table]['num_rows']
        return table_offset

    def get_stream_start(self, stream_id):
        metadata_header_offset = self.get_metadata_header_offset()
        hit = self.file_data.find(stream_id)
        if hit == -1:
            raise ErrorHandling(
                f'Unable to find offset of stream {stream_id}'
            )
        stream_offset = self.bytes_to_int(self.file_data[hit - 8:hit - 4])
        return metadata_header_offset + stream_offset


    def retrieve_translated_config(self):
        logger.debug(
            f'Translating Config...'
        )
        translated_config = {}
        for (us_rva, strings_rva) in self.config_addr_map:
            try:
                field_name = self.rva_string_to_rva_value(strings_rva)
                field_value = self.us_rva_to_us_val(us_rva)
                logger.debug(
                    f'Found Config Values: {field_name}: {field_value}'
                )
                translated_config[field_name] = field_value
            except Exception as e:
                raise ErrorHandling(
                    f'Error while retrieving the translated config {hex(us_rva)}, {hex(strings_rva)}'
                ) from e
        logger.debug(
            f'Successfully retrieved translated config...'
        )
        return translated_config

    def get_metadata_header_offset(self):
        hit = self.file_data.find(self.PATTERN_CLR_METADATA_START)
        if hit == -1:
            raise ErrorHandling(
                f"Couldn't Find CLR MetaData Header"
            )
        return hit


    def get_string_from_offset(self, str_offset, delimiter=b'\0'):
        try:
            result = self.file_data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise ErrorHandling(
                f'Error Retrieving offset from: {str_offset} with the delimiter: {delimiter}'
            ) from e
        return result

    def bytes_to_int(self, bytes, order='little'):
        try:
            result = int.from_bytes(bytes, byteorder=order)
        except Exception as e:
            raise ErrorHandling(
                f'Error Parsing int from value: {bytes}'
            ) from e
        return result

    def extract_mask_valid(self):
        try:
            logger.debug(
                f'Extracting M_MaskValid Value for {self.file_path}'
            )
            storage_stream_offset = self.get_stream_start(self.STREAM_IDENTIFIER_STORAGE)
            mask_valid_offset = storage_stream_offset + 8
            mask_valid = self.bytes_to_int(self.file_data[mask_valid_offset:mask_valid_offset + 8])
            logger.debug(
                f'Extracted M_MaskValid: {hex(mask_valid)}'
            )
        except Exception as e:
            raise ErrorHandling(
                f'Error Occurred while attempting to return Mask_Valid ID for {self.file_path}'
            ) from e
        return mask_valid

    def us_rva_to_us_val(self, us_rva):
        us_start = self.get_stream_start(self.STREAM_IDENTIFIER_US)
        length_byte_offset = us_rva - self.RVA_US_BASE + us_start
        if (self.file_data[length_byte_offset]) & 0x80:
            val_offset = 2
            val_size = self.bytes_to_int(self.file_data[length_byte_offset:length_byte_offset + 2], 'big') - 0x8000
        else:
            val_offset = 1
            val_size = self.file_data[length_byte_offset]
        val_offset += length_byte_offset
        us_val = self.file_data[val_offset:val_offset + val_size - 1]
        return us_val

    def rva_string_to_rva_value(self, rva_string):
        val_index = rva_string - self.RVA_STRING_BASE - 1
        try:
            strings_val = self.fields_map[val_index][0]
        except Exception as e:
            raise ErrorHandling(
                f'Error retrieving string from RVA: {rva_string}'
            ) from e
        return strings_val

    def decode_strings(self, byte_str):
        try:
            if b'\x00' in byte_str:
                result = byte_str.decode('utf-16le')
            else:
                result = byte_str.decode('utf-8')
        except Exception as e:
            raise ErrorHandling(
                f'Error while decoding {byte_str}'
            ) from e
        return result

    def decrypted_config(self):
        logger.debug(
            f'Decrypting Config'
        )
        decrypted_info = {}
        for k, v in self.translated_config.items():
            decoded_k = self.decode_strings(k)
            decrypted_info[decoded_k] = self.decode_strings(v)
        return decrypted_info