rule Lokibot {
	meta:
		Description = "Lokibot Detection"
		Author = "PotatoPrn"
		Date = "2023-09-26"

	strings:
		$String = "Fuckav.ru"
		$Hex1 = {8b 75 ?? eb 1a 0f b6 06 4a 33 c8 46 6a ?? 58 f6 c1 ?? 74 06 81 f1 ?? ?? ?? ?? d1 e9 48}
		$Hex2 = {c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ??}


	condition:
		uint16(0) == 0x5A4D and all of ($Hex*) or
		uint16(0) == 0x5A4D and $String
}