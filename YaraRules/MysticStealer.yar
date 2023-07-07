rule MysticStealer {
	meta: 
		Description = "Mystic Stealer Detection"
		Author = "PotatoTech"
		Date = "2023-07-07"
		Hash = "e4f69bc279e734da4c749ac53620ad3e5a9da25bce30d5dc9c240faaf8f1b16f"


	strings:
		$Hex1 = { 89 45 40 8d 45 88 89 45 44 8d 45 ec 89 45 48 8d 45 bc 89 45 4c 8d 85 6c ff ff ff 89 45 50 8d 45 d4 89 45 54 8d 45 a4 89 45 58 8d 45 18 89 45 5c 8d 45 04 89 45 60 }
		$Hex2 = { 89 84 24 64 01 00 00 8d 84 24 e0 05 00 00 89 84 24 68 01 00 00 8d 84 24 88 08 00 00 89 84 24 6c 01 00 00 8d 84 24 70 07 00 00 }

	condition:
		uint16(0) == 0x5A4D and all of them
}