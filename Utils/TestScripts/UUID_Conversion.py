uuid = 0x1234567890abcdef1234567890abcdef
uuid_str = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" % (
    uuid >> 96,
    (uuid >> 80) & 0xffff,
    (uuid >> 64) & 0xffff,
    (uuid >> 56) & 0xff,
    (uuid >> 48) & 0xff,
    (uuid >> 40) & 0xff,
    (uuid >> 32) & 0xff,
    (uuid >> 24) & 0xff,
    (uuid >> 16) & 0xff,
    (uuid >> 8) & 0xff,
    uuid & 0xff,
)
print(uuid_str)