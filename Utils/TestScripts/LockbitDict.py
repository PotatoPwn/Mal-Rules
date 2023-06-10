#!/usr/env python

from struct import pack, unpack

def decrypt_string():
	listitems = []
	for item in brug:
		byte_val = bytes.fromhex(hex(item)[2:])
		byte_val = bytes([x ^ y for x, y in zip(byte_val, b'\x10\x03\x5f\xff')])
		byte_val = ([~b & 0xff for b in byte_val])
		val = int.from_bytes(byte_val, 'little', signed=True)
		pVal = pack("<i", val)
		pVal = pVal[1:]
		print(pVal)

brug = [
0x2479f5cc,
0xfe2d3128,
0x2ffc3bad,
0x1001784f
]


decrypt_string()

#print(brug)