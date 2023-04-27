rule Redline_Hunter {
	meta:
		author = "Potato"
		description = "Unpacked RedLine Hunter"

    strings:
        $Config = {
        	00					// NOP
            72 ?? ?? ?? 70		// LDSTR 
            80 ?? ?? ?? 04      // STSFLD <IP>
            72 ?? ?? ?? 70		// LDSTR
            80 ?? ?? ?? 04      // STSFLD <ID>
            72 ?? ?? ?? 70		// LDSTR
            80 ?? ?? ?? 04      // STSFLD <MESSAGE>
            72 ?? ?? ?? 70		// LDSTR
            80 ?? ?? ?? 04      // STSFLD <KEY>
            17                  // ldc.i4.1
            80 ?? ?? ?? 04      // STSFLD <VERSION>
            2A                  // ret

        }
    
    condition:
    	uint16(0) == 0x5A4D and $Config
}
