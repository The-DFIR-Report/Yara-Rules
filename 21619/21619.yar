rule mal_truebot: TESTING MALWARE TA0002 T1027 T1204_002 {
    meta:
        id = "2snLTJeZ4eKhhGLfWNM6NV"
        fingerprint = "03f4fb857eaf63b4ce33611cce6c9f06e57180c122d28305bc7d7d2cb839ef27"
        version = "1.0"
        creation_date = "2023-05-25"
        first_imported = "2023-05-25"
        last_modified = "2023-05-25"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THEDFIRREPORT.COM"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects strings commonly related to TrueBot functionality"
        category = "MALWARE"
        malware = "TRUEBOT"
        mitre_att = "T1204.002"
        reference = "https://thedfirreport.com/"
        hash = "717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb"

    strings:
        $c2_params_1        = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" fullword
        $c2_params_2        = "n=%s&l=%s"   fullword
        $c2_id              = "%08x-%08x"   fullword
        $c2_status          = "Not Found"   fullword
        $c2_method          = "POST "       fullword
        $c2_proto           = "HTTP/1.0"    fullword
        $c2_header_host     = "Host: "      fullword
        $c2_header_ct       = "Content-type: application/x-www-form-urlencoded" fullword
        $other_workgroup    = "WORKGROUP"           fullword
        $other_unknown      = "UNKW"                fullword
        $load_perms         = "SeDebugPrivilege"    fullword
        $load_library       = "user32"              fullword wide
        $load_import        = "RtlCreateUserThread" fullword
        $cmd_del            = "/c del" fullword wide

    condition:
        13 of them
}

rule sus_nsis_tampered_signature: TESTING SUSPICIOUS TA0005 T1027 T1027_005 {
    meta:
        id = "7tGWOPTZRLhRAMCf6cQC0"
        fingerprint = "082b47efe4dbb5ff515f2db759233fc39238bf4982aa0884b809232686c49531"
        version = "1.0"
        creation_date = "2023-06-01"
        first_imported = "2023-06-01"
        last_modified = "2023-06-01"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THEDFIRREPORT.COM"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a suspected Nullsoft Scriptable Install System (NSIS) executable with a tampered compiler signature"
        category = "TOOL"
        tool = "NSIS"
        mitre_att = "T1027.005"
        reference = "https://thedfirreport.com/"
        hash = "121a1f64fff22c4bfcef3f11a23956ed403cdeb9bdb803f9c42763087bd6d94e"

    strings:
        $brand_error       = "NSIS Error"                      fullword
        $brand_description = "Nullsoft Install System"         fullword
        $brand_name        = "Nullsoft.NSIS"                   fullword 
        $brand_url         = "http://nsis.sf.net/NSIS_Error"   fullword
        $code_get_module        = {
            C1 E6 03            // shl     esi, 3
            8B BE ?? ?? ?? ??   // mov     edi, Modules[esi]
            57                  // push    edi             ; lpModuleName
            FF 15 ?? ?? ?? ??   // call    ds:GetModuleHandleA
            85 C0               // test    eax, eax
            75 ??               // jnz     ??
        }
        $code_get_proc          = {
            FF B6 ?? ?? ?? ??   // push    Procedures[esi]
            50                  // push    eax             ; hModule
            FF 15 ?? ?? ?? ??   // call    ds:__imp_GetProcAddress
            EB ??               // jmp     ??
        }
        $code_jump_table        = {
            8B 4D ??                // mov     ecx, [ebp+??]
            83 C1 ??                // add     ecx, 0FFFFFF??h ; switch ?? cases
            83 F9 ??                // cmp     ecx, ??h
            0F 87 ?? ?? 00 00       // ja      ??      ; jumptable ?? default case, cases 65,66
            FF 24 8D ?? ?? ?? 00    // jmp     ds:??[ecx*4] ; switch jump
        }
        $signature_1_00         = {EF BE AD DE 6E 73 69 73 69 6E 73 74 61 6C 6C 00}
        $signature_1_00_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 61 6C 6C 00    // cmp     [ebp+??], 06C6C61h
            75 ??                   // jnz     short ??
            81 7D ?? 69 6E 73 74    // cmp     [ebp+var_1C], 74736E69h
            75 ??                   // jnz     short ??
            81 7D ?? 6E 73 69 73    // cmp     [ebp+??], 7369736Eh
            75 ??                   // jnz     ??
        }
        $signature_1_1e         = {ED BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74}
        $signature_1_1e_check   = {
            81 7D ?? ED BE AD DE    // cmp     [ebp+??], 0DEADBEEDh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 53 6F 66 74    // cmp     [ebp+var_1C], 74666F53h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }
        $signature_1_30         = {EF BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74}
        $signature_1_30_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 53 6F 66 74    // cmp     [ebp+var_1C], 74666F53h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }
        $signature_1_60         = {EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74}
        $signature_1_60_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 73 6F 66 74    // cmp     [ebp+var_1C], 74666F73h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }

    condition:
        uint16(0) == 0x5A4D and (3 of ($brand_*) or 2 of ($code_*)) and none of ($signature_*)
}
