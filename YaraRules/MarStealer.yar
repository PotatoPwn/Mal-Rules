rule MarsStealer {
	meta:
		description = "MarsStealer Detection"
		Author = "PotatoPrn"
		Date = "13/01/2024"

	strings:
		$Hex1 = {61 73 64 6c 30 71 77 69 8d 5b 01}
		$Hex2 = {8b 40 0c 8b 40 14 8b 78 10}


	condition:
		uint16(0) == 0x5A4D and all of them
}