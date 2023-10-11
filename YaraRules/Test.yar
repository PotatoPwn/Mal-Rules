rule TestDetection {
	meta: 
		Description = "FormBook Detection"
		Author = "Potattech"
		Date = "2023-08-22"

	strings:
		$String1 = "Test123"

	condition:
		any of them
}