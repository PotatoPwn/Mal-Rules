#!/usr/env python

hex_vals = [
	0xefa0a05c,
	0xef95a070,
	0xef99a070,
	0xefd9a05c,
	0xeffca073
]

result = []
for value in hex_vals:
	xored_val = value ^ 0x10035fff
	xored_hex = hex(xored_val)
	binary_val = bin(int(xored_hex, 16))[2:]
	not_op = ~int(binary_val, 2)
	final = hex(not_op)
	print(int(final, 16))
	result.append(final)

print(result)

# Xor 
#xored_val = hex_vals ^ 0x10035fff

#binary_val = bin(xored_val)

#notted = ~xored_val

#print(binary_val)