import re
from argparse import ArgumentParser
from logging import basicConfig, DEBUG, getLogger, WARNING
from re import DOTALL, findall, search
from hashlib import md5
from base64 import b64decode
from json import dumps

from Crypto.Cipher import AES

logger = getLogger(__name__)

class XWormError(Exception):
    pass

class XWormParser:

    PATTERN_CONFIG_START = b'(\x72.{9}){3}'
    PATTERN_PARSED_RVA = b'\x72(.{4})\x80(.{4})'
    PATTERN_CLR_METADATA_START = b'\x42\x53\x4a\x42'
    RET_CODE = b'\x2A'
    STREAM_ID_STORAGE = b'#~'
    STREAM_ID_STRINGS = b'#Strings'
    STREAM_ID_US = b'#US'
    TABLE_FIELD = 'Field'
    RVA_US_BASE = 0x70000000
    RVA_STRING_BASE = 0x4000000

    MAP_TABLE = {
        'Module': {
            'row_size': 10
        },
        'TypeRef': {
            'row_size': 6
        },
        'TypeDef': {
            'row_size': 14
        },
        'FieldPtr': {
            'row_size': 2
        },
        'Field': {
            'row_size': 6
        },
        'MethodPtr': {
            'row_size': 2
        },
        'Method': {
            'row_size': 14
        },
        'ParamPtr': {
            'row_size': 2
        },
        'Param': {
            'row_size': 6
        },
        'InterfaceImpl': {
            'row_size': 4
        },
        'MemberRef': {
            'row_size': 6
        },
        'Constant': {
            'row_size': 6
        },
        'CustomAttribute': {
            'row_size': 6
        },
        'FieldMarshal': {
            'row_size': 4
        },
        'DeclSecurity': {
            'row_size': 6
        },
        'ClassLayout': {
            'row_size': 8
        },
        'FieldLayout': {
            'row_size': 6
        },
        'StandAloneSig': {
            'row_size': 2
        },
        'EventMap': {
            'row_size': 4
        },
        'EventPtr': {
            'row_size': 2
        },
        'Event': {
            'row_size': 6
        },
        'PropertyMap': {
            'row_size': 4
        },
        'PropertyPtr': {
            'row_size': 2
        },
        'Property': {
            'row_size': 6
        },
        'MethodSemantics': {
            'row_size': 6
        },
        'MethodImpl': {
            'row_size': 6
        },
        'ModuleRef': {
            'row_size': 2
        },
        'TypeSpec': {
            'row_size': 2
        },
        'ImplMap': {
            'row_size': 8
        },
        'FieldRVA': {
            'row_size': 6
        },
        'ENCLog': {},
        'ENCMap': {},
        'Assembly': {},
        'AssemblyProcessor': {},
        'AssemblyOS': {},
        'AssemblyRef': {},
        'AssemblyRefProcessor': {},
        'AssemblyRefOS': {},
        'File': {},
        'ExportedType': {},
        'ManifestResource': {},
        'NestedClass': {},
        'GenericParam': {},
        'MethodSpec': {},
        'GenericParamConstraint': {},
        'Reserved 2D': {},
        'Reserved 2E': {},
        'Reserved 2F': {},
        'Document': {},
        'MethodDebugInformation': {},
        'LocalScope': {},
        'LocalVariable': {},
        'LocalConstant': {},
        'ImportScope': {},
        'StateMachineMethod': {},
        'CustomDebugInformation': {},
        'Reserved 38': {},
        'Reserved 39': {},
        'Reserved 3A': {},
        'Reserved 3B': {},
        'Reserved 3C': {},
        'Reserved 3D': {},
        'Reserved 3E': {},
        'Reserved 3F': {}
    }
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = self.retrieve_file_data()
        self.table_map = self.get_table_map()
        self.fields_map = self.get_fields_map()
        self.config_addr_map = self.get_config_addr_map()
        self.translated_config = self.retrieve_translated_config()
        self.decrypted_strings = self.decrypted_config()
        self.encryption_key = self.generate_aes_key()


    def retrieve_file_data(self):
        logger.debug(
            f'Retrieving Contents from: {self.file_path}'
        )
        try:
            with open(self.file_path, 'rb') as fp:
                data = fp.read()
        except Exception as e:
            raise XWormError(
                f'Error reading Content from: {self.file_path}'
            ) from e
        logger.debug(
            f'Data was Successfully read'
        )
        return data

    def get_config_addr_map(self):
        logger.debug(
            f'Extracting Config Address Map'
        )
        config_mappings = []
        hit = search(self.PATTERN_CONFIG_START, self.file_data, DOTALL)
        if hit is None:
            raise XWormError(
                f'Error Searching for start of pattern'
            )
        config_start = hit.start()
        logger.debug(
            f'Found Config Start at: {config_start}'
        )
        parsed_ops = self.get_string_from_offset(config_start, self.RET_CODE)
        parsed_rvas = findall(self.PATTERN_PARSED_RVA, parsed_ops, DOTALL)
        for (us_rva, string_rva) in parsed_rvas:
            config_value_rva = self.bytes_to_int(us_rva)
            config_name_rva = self.bytes_to_int(string_rva)
            logger.debug(
                f'Found Config Item: ({hex(config_value_rva)}, {hex(config_name_rva)})'
            )
            config_mappings.append((config_value_rva, config_name_rva))
        logger.debug(
            f'Config Map extraction was successful'
        )
        return config_mappings

    def get_table_map(self):
        logger.debug(
            f'Extracting Table Map...'
        )
        mask_valid = self.extract_mask_valid()
        table_map = self.MAP_TABLE.copy()
        storage_stream_offset = self.get_stream_start(
            self.STREAM_ID_STORAGE
        )
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
                    table_map[table]['num_rows'] = 0
        except Exception as e:
            raise XWormError(
                f'Unable to get counts of row from table'
            ) from e
        logger.debug(
            f'Successfully extracted Table Map'
        )
        return table_map


    def extract_mask_valid(self):
        logger.debug(
            f'Extracting m_maskvalid value...'
        )
        storage_stream_offset = self.get_stream_start(
            self.STREAM_ID_STORAGE
        )
        mask_valid_offset = storage_stream_offset + 8
        mask_valid = self.bytes_to_int(
            self.file_data[mask_valid_offset:mask_valid_offset + 8]
        )
        logger.debug(f'Extracted m_maskvalid: {hex(mask_valid)}')
        return mask_valid

    def get_metadata_header_offset(self):
        hit = self.file_data.find(self.PATTERN_CLR_METADATA_START)
        if hit == -1:
            raise XWormError(
                'Couldnt find CLR MetaData Header'
            )
        return hit

    def get_stream_start(self, stream_id):
        metadata_header_offset = self.get_metadata_header_offset()
        hit = self.file_data.find(stream_id)
        if hit == -1:
            raise XWormError(
                f'Unable to find offset of stream {stream_id}'
            )
        stream_offset = self.bytes_to_int(self.file_data[hit - 8:hit -4])
        return metadata_header_offset + stream_offset

    def retrieve_translated_config(self):
        logger.debug(
            f'translating config...'
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
                raise XWormError(
                    f'Error while retrieving the translated config {hex(us_rva)}, {hex(strings_rva)}'
                ) from e
        logger.debug(
            f'Successfully retrieved translated config...'
        )
        return translated_config

    def get_fields_map(self):
        logger.debug(
            f'Extracting Fields Map...'
        )
        fields_map = []
        fields_start = self.get_table_start(self.TABLE_FIELD)
        strings_start = self.get_stream_start(self.STREAM_ID_STRINGS)
        cur_offset = fields_start
        for x in range(self.table_map[self.TABLE_FIELD]['num_rows']):
            try:
                field_offset = self.bytes_to_int(self.file_data[cur_offset+2:
                                                                cur_offset+4])
                field_value = self.get_string_from_offset(strings_start+
                                                          field_offset)
                cur_offset += self.table_map[self.TABLE_FIELD]['row_size']
            except Exception as e:
                raise XWormError(
                    f'Error while parsing field table'
                ) from e
            logger.debug(
                f'Successfully extracted fields map with the fields \n'
                f'{hex(field_offset)}, {field_value}'
            )
            fields_map.append((field_value, field_offset))
        return fields_map



    def get_table_start(self, table_name):
        storage_stream_offset = self.get_stream_start(
            self.STREAM_ID_STORAGE
        )
        tables_start_offset = storage_stream_offset + 24 + (4 * len([
            table for table in self.table_map
            if self.table_map[table]['num_rows'] > 0
        ]))
        table_offset = tables_start_offset
        for table in self.table_map:
            if table == table_name:
                break
            elif 'row_size' not in self.table_map[table]:
                raise XWormError(
                    f'Invalid Table offset Found'
                )
            table_offset += self.table_map[table]['row_size'] * self.table_map[
                table]['num_rows']
        return table_offset

    def us_rva_to_us_val(self, us_rva):
        us_start = self.get_stream_start(self.STREAM_ID_US)
        length_byte_offset = us_rva - self.RVA_US_BASE + us_start
        if (self.file_data[length_byte_offset]) & 0x80:
            val_offset = 2
            val_size = self.bytes_to_int(self.file_data[length_byte_offset:length_byte_offset+2], 'big') - 0x8000
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
            raise XWormError(
                f'Error retreiving string from RVA {rva_string}'
            ) from e
        return strings_val

    def bytes_to_int(self, bytes, order='little'):
        try:
            result = int.from_bytes(bytes, byteorder=order)
        except Exception as e:
            raise XWormError(
                f'Error parsing int from value: {bytes}'
            ) from e
        return result

    def get_string_from_offset(self, str_offset, delimiter=b'\0'):
        try:
            result = self.file_data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise XWormError(
                f'Error Retrieving String from offset: {str_offset} with the chose delimiter: {delimiter}'
            ) from e
        return result

    def decode_string(self, byte_str):
        try:
            if b'\x00' in byte_str:
                result = byte_str.decode('utf-16le')
            else:
                result = byte_str.decode('utf-8')
        except Exception as e:
            raise XWormError(
                f'Error while decoding {byte_str}'
            ) from e
        return result
    def decrypted_config(self):
        logger.debug(
            f'Decrypting Config'
        )
        decrypted_info = {}
        for k, v in self.translated_config.items():
            decoded_k = self.decode_string(k)
            decrypted_info[decoded_k] = self.decode_string(v)
        return decrypted_info
    def generate_aes_key(self):
        logger.debug(
            f'Generating AES Key'
        )
        mutex = (list(self.decrypted_strings.values()))[-1]
        mutex_hash = md5(bytes(mutex, 'UTF-8')).hexdigest()
        result = mutex_hash[:30] + mutex_hash + '00'
        return result

    def decrypt_host(self):
        host = (list(self.decrypted_strings.values()))[0]
        try:
            result = self.aes_decrypt(b64decode(host))
            return result
        except:
            return host

    def decrypt_port(self):
        port = (list(self.decrypted_strings.values()))[1]
        try:
            result = self.aes_decrypt(b64decode(port))
            return re.sub(r'\f', "", result)
        except:
            return None

    def aes_decrypt(self, data):
        aes_key = AES.new((bytes.fromhex(self.generate_aes_key())), AES.MODE_ECB)
        return aes_key.decrypt(data).decode()


    def report(self):
        result = {
            'file_Path': self.file_path,
            'Mutex': (list(self.decrypted_strings.values()))[-1],
            'IP/URL': self.decrypt_host(),
            'Port': self.decrypt_port(),
            'AES_Key': self.generate_aes_key()
        }
        return result


if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument(
        'file_paths',
        nargs='+',
        help=f'One or more deobfuscated Xworm Samples')
    ap.add_argument(
        '-d',
        '--debug',
        action='store_true',
        help='Enables Debugging')
    args = ap.parse_args()
    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)

    decrypted_config = []
    for fp in args.file_paths:
        try:
            decrypted_config.append(XWormParser(fp).report())
        except:
            logger.debug(f'Exception occurred for {fp}', exc_info=True)
            continue
    if len(decrypted_config) > 0:
        print(dumps(decrypted_config, indent=2))
