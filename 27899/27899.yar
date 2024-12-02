rule VeeamHax
{
    meta:
        description = "exe - file VeeamHax.exe"
		author = "The DFIR Report, _pete_0"
		reference = "https://thedfirreport.com/2024/12/02/the-curious-case-of-an-egg-cellent-resume/"
                reference = "https://github.com/sfewer-r7/CVE-2023-27532"
		date = "2024-11-15"
		hash1 = "AAA6041912A6BA3CF167ECDB90A434A62FEAF08639C59705847706B9F492015D"
        
    strings:
        $String_1 = "CVE-2023-27532" ascii wide nocase
        $String_2 = "VeeamHax" ascii wide nocase
        $String_3 = "Veeam Backup Server Certificate" ascii wide nocase
        $String_4 = "EXEC sp_configure" ascii wide nocase
        $String_5 = "xp_cmdshell" ascii wide nocase
        $String_6 = "Veeam.Backup.Interaction.MountService" ascii wide nocase

    condition:
		uint16(0) == 0x5a4d and filesize < 100KB and
        all of ($String_*)
}
