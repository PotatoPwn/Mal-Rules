rule PovertyStealer {
	meta:
		Description = "Poverty Stealer"
		AUthor = "PotatoPrn"
		Date = "2023-10-11"

	strings:
		$String1 = "Adapter #%d: %s"
		$String2 = "ScreenSize: {lWidth=%d, lHeight=%d}"
		$String3 = "Poverty is the parent of crime"
		$String4 = "SystemLayout %d"
		$String5 = "HWID: %s"
		$String6 = "VideoAdapter #%d"
		$String7 = "OperationSystem: %d:%d"
		$String8 = "KeyboardLayouts: ("
		$String9 = "{%d}"





	condition:
		uint16(0) == 0x5A4D and 6 of ($String*)
}