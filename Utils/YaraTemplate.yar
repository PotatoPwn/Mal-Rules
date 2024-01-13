rule SigName {
	meta:
		description = ""
		Author = "PotatoPrn"
		Date = ""

	strings:


	condition:
		uint16(0) == 0x5A4D

}