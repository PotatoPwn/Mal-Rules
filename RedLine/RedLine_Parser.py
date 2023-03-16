#!/usr/bin/env python3


from argparse import ArgumentParser

from json import dumps
from logging import basicConfig, DEBUG, getLogger, WARNING
from re import DOTALL, findall, search
from base64 import b64decode, b64encode
from itertools import cycle

logger = getLogger(__name__)


class RedLineParser:

    OPCODE_RET = b'\x2a'
    PATTERN_CLR_METADATA_START = b'\x42\x53\x4a\x42'
    PATTERN_CONFIG_START = b'(\x72.{9}){4}'
    PATTERN_PARSED_RVAS = b'\x72(.{4})\x80(.{4})'
    STREAM_IDENTIFIER_STORAGE = b'#~'
    STREAM_IDENTIFIER_STRINGS = b'#Strings'
    STREAM_IDENTIFIER_US = b'#US'
    TABLE_FIELD = 'Field'
    RVA_US_BASE = 0x70000000
    RVA_STRING_BASE = 0x04000000

    # This map assists in calculating offsets for Field and FieldRVA entries.
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

    class RedLine_Error(Exception):
        pass

    def __init__(self, file_path):
        self.file_path = file_path
        self.data = self.get_file_data()
        self.table_map = self.get_table_map()
        self.fields_map = self.get_fields_map()
        self.config_addr_map = self.get_config_address_map()
        self.translated_Config = self.get_translated_config()
        self.decrypted_Config = self.decrypt_config()
        self.decrypt_ip_info = self.decrypt_IP()



    def bytes_to_int(self, bytes, order='little'):
        try:
            result = int.from_bytes(bytes, byteorder=order)
        except Exception as e:
            raise self.RedLine_Error(
                f'Error parsing int from value: {bytes}') from e
        return result


    def get_config_address_map(self):
        logger.debug('Extracting the config address map...')
        config_mappings = []
        hit = search(self.PATTERN_CONFIG_START, self.data, DOTALL)
        if hit is None:
            raise self.RedLine_Error('Could not find start of config')
        config_start = hit.start()
        # Search for all opcodes that match the string with the end as a ret since our config ends with a ret
        parsed_ops = self.get_string_from_offset(config_start, self.OPCODE_RET)
        parsed_rvas = findall(self.PATTERN_PARSED_RVAS, parsed_ops, DOTALL)
        for (us_rva, string_rva) in parsed_rvas:
            config_value_rva = self.bytes_to_int(us_rva)
            config_name_rva = self.bytes_to_int(string_rva)
            logger.debug(
                f'Found config item: ({hex(config_value_rva)}, {hex(config_name_rva)})'
            )
            config_mappings.append((config_value_rva, config_name_rva))
        logger.debug('Successfully extracted config address map')
        return config_mappings

    def get_translated_config(self):
        # Translate the field RVA to the value in our field map
        # Translated_Config[key] = value
        logger.debug('Translating Config')
        translated_Config = {}
        for (us_rva, strings_rva) in self.config_addr_map:
            try:
                field_name = self.rva_string_to_value_rva(strings_rva)
                field_value = self.us_rva_to_us_val(us_rva)
                logger.debug(f'Found a config value: {field_name} = {field_value}')
                translated_Config[field_name] = field_value
            except Exception as e:
                raise self.RedLine_Error(f' Error translating RVAs {hex(us_rva)} and {hex(strings_rva)}') from e
        logger.debug('Successfully translated config')
        return translated_Config

    def decrypt_config(self):
        logger.debug('Decrypting Config')
        decrypted_Config = {}
        for k,v in self.translated_Config.items():
            decoded_K = self.decode_string(k)
            b64_Exception = False
            decrypted_Config[decoded_K] = self.decode_string(v)
            if len(v) == 0:
                continue
            try:
                decoded_val = b64decode(v)
            except:
                b64_Exception = True

            if b64_Exception or len(decoded_val) < 48:
                logger.debug(f'Key: {decoded_K}, Value {decrypted_Config[decoded_K]}')
                continue
        return decrypted_Config

    def decrypt_IP(self):
        config_info = self.decrypted_Config
        address = config_info["IP"]
        key = config_info["Key"]
        result = self.xor_crypt_string(address, bytes(key, 'utf-8'))
        return (b64decode(result).decode())

    @staticmethod
    def xor_crypt_string(data, key, encode = False, decode = True):
        if decode:
            data = b64decode(data)
        xored = ''.join(chr(x ^ y) for (x,y) in zip(data, cycle(key)))
        if encode:
        # return base64.encodestring(xored).strip()
            return b64encode(xored.encode('utf-8')).decode('utf-8').replace('\n', '').strip()
        return xored


    def decode_string(self, byte_str):
        try:
            if b'\x00' in byte_str:
                result = byte_str.decode('utf-16le')
            else:
                result = byte_str.decode('utf-8')
        except Exception as e:
            raise self.RedLine_Error(f'Unable to decode to unicode {byte_str}')
        return result

    def us_rva_to_us_val(self, us_rva):
        us_Start = self.get_stream_start(self.STREAM_IDENTIFIER_US)
        # length_byte_offset = (IP)0x70000911 - 0x70000000 + file offset for Strings Start
        length_byte_offset = us_rva - self.RVA_US_BASE + us_Start
        if (self.data[length_byte_offset]) & 0x80:
            val_offset = 2
            val_size = self.bytes_to_int(self.data[length_byte_offset:length_byte_offset+2], 'big') - 0x8000
        else:
            val_offset = 1
            val_size = self.data[length_byte_offset]
        # 0x70000911 + 1
        val_offset += length_byte_offset
        us_val = self.data[val_offset:val_offset + val_size - 1]
        return us_val

    def rva_string_to_value_rva(self, rva_string):
        # IP is on token 0x04000013
        # Indexing IP = 0x04000013 - 0x04000000 - 13 = 0
        val_Index = rva_string - self.RVA_STRING_BASE - 1
        try:
            strings_val = self.fields_map[val_Index][0]
        except Exception as e:
            raise self.RedLine_Error(f'Couldnt retrieve string from RVA {rva_string}') from e
        return strings_val

    def get_fields_map(self):
        # Extract field table and map each value to correct field
        logger.debug('Extracting fields map...')
        fields_map = []
        fields_start = self.get_table_start(self.TABLE_FIELD)
        strings_start = self.get_stream_start(self.STREAM_IDENTIFIER_STRINGS)
        cur_offset = fields_start
        for x in range(self.table_map[self.TABLE_FIELD]['num_rows']):
            try:
                field_offset = self.bytes_to_int(self.data[cur_offset +
                                                           2:cur_offset + 4])
                field_value = self.get_string_from_offset(strings_start +
                                                          field_offset)
                cur_offset += self.table_map[self.TABLE_FIELD]['row_size']
            except Exception as e:
                raise self.RedLine_Error(
                    'Error parsing Field table') from e
            logger.debug(f'Found field: {hex(field_offset)}, {field_value}')
            fields_map.append((field_value, field_offset))
        logger.debug('Successfully extracted fields map')
        return fields_map

    def get_file_data(self):
        logger.debug(f'Reading contents from: {self.file_path}')
        try:
            with open(self.file_path, 'rb') as fp:
                data = fp.read()
        except Exception as e:
            raise self.RedLine_Error(
                f'Error reading from path: {self.file_path}') from e
        logger.debug('Successfully read data')
        return data

    def get_mask_valid(self):
        logger.debug('Extracting m_maskvalid value...')
        storage_stream_offset = self.get_stream_start(
            self.STREAM_IDENTIFIER_STORAGE)
        mask_valid_offset = storage_stream_offset + 8
        mask_valid = self.bytes_to_int(
            self.data[mask_valid_offset:mask_valid_offset + 8])
        logger.debug(f'Extracted m_maskvalid: {hex(mask_valid)}')
        return mask_valid


    def get_metadata_header_offset(self):
        hit = self.data.find(self.PATTERN_CLR_METADATA_START)
        if hit == -1:
            raise self.RedLine_Error(
                'Could not find start of CLR metadata header')
        return hit


    def get_stream_start(self, stream_identifier):
        metadata_header_offset = self.get_metadata_header_offset()
        hit = self.data.find(stream_identifier)
        if hit == -1:
            raise self.RedLine_Error(
                f'Could not find offset of stream {stream_identifier}')
        stream_offset = self.bytes_to_int(self.data[hit - 8:hit - 4])
        return metadata_header_offset + stream_offset

    def get_string_from_offset(self, str_offset, delimiter=b'\0'):
        try:
            result = self.data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise self.RedLine_Error(
                f'Could not extract string value from offset {hex(str_offset)} with delimiter {delimiter}'
            ) from e
        return result

    def get_table_map(self):
        logger.debug('Extracting table map...')
        mask_valid = self.get_mask_valid()

        table_map = self.MAP_TABLE.copy()
        storage_stream_offset = self.get_stream_start(
            self.STREAM_IDENTIFIER_STORAGE)

        table_start = storage_stream_offset + 24
        cur_offset = table_start
        try:
            for table in table_map:
                if mask_valid & (2**list(table_map.keys()).index(table)):
                    row_count_packed = self.data[cur_offset:cur_offset + 4]
                    row_count = self.bytes_to_int(row_count_packed)
                    table_map[table]['num_rows'] = row_count
                    logger.debug(f'Found {row_count} rows for table {table}')
                    cur_offset += 4
                else:
                    table_map[table]['num_rows'] = 0
        except Exception as e:
            raise self.RedLine_Error(
                'Could not get counts of rows from tables') from e
        logger.debug('Successfully extracted table map')
        return table_map

    def report(self):
        result_dict = {
            'file_path': self.file_path,
            'ID': self.decrypted_Config['ID'],
            'KEY': self.decrypted_Config['Key'],
            'IP': self.decrypt_ip_info,
            'Message': self.decrypted_Config['Message']
        }
        return result_dict

    def get_table_start(self, table_name):
        storage_stream_offset = self.get_stream_start(
            self.STREAM_IDENTIFIER_STORAGE)
        tables_start_offset = storage_stream_offset + 24 + (4 * len([
            table for table in self.table_map
            if self.table_map[table]['num_rows'] > 0
        ]))

        table_offset = tables_start_offset
        for table in self.table_map:
            if table == table_name:
                break
            elif 'row_size' not in self.table_map[table]:
                raise self.RedLine_Error('Invalid table offset found')
            table_offset += self.table_map[table]['row_size'] * self.table_map[
                table]['num_rows']
        return table_offset



if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument(
        'file_paths',
        nargs='+',
        help='One or more RedLine payload file paths (deobfuscated)')
    ap.add_argument('-d',
                    '--debug',
                    action='store_true',
                    help='Enable debug logging')
    args = ap.parse_args()
    if args.debug:
        basicConfig(level=DEBUG)
    else:
        basicConfig(level=WARNING)

    decrypted_Config = []
    for fp in args.file_paths:
        try:
            decrypted_Config.append(RedLineParser(fp).report())
        except:
            logger.exception(f'Exception occurred for {fp}', exc_info=True)
            continue
    if len(decrypted_Config) > 0:
        print(dumps(decrypted_Config))