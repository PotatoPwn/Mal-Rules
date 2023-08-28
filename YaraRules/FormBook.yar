rule FormBook {
	meta: 
		Description = "FormBook Detection"
		Author = "Potattech"
		Date = "2023-08-22"

	strings:
		$Hex1 = {55 8b ec 8b 45 08 8b 48 10 56 ?? ?? ?? ?? 51 }
		$Hex2 = {55 8b ec 8b ?? ?? 85 c9 ?? ?? }

	condition:
		uint16(0) == 0x5A4D and all of them
}