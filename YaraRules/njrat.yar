rule njrat {
	meta:
	    author = "Potato"
	    description = "yara rule for unpacked njrats"

	strings: 
		$St1 = "Select * From AntiVirusProduct" ascii wide
		$St2 = "Execute ERROR" ascii wide
		$St3 = "prof" ascii wide
		$St4 = "Update ERROR" ascii wide
		$St5 = "??-??-??" ascii wide
		$St6 = "winmgmts:" ascii wide
		$St7 = "TcpClient"
		$St8 = "ReadAllBytes"



	condition:
		uint16(0) == 0x5A4D and all of them
}