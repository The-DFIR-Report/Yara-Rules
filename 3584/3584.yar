/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-05-09
Identifier: Case 3584 Conti Ransomware
Reference: https://thedfirreport.com/2021/05/12/conti-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule icedid_rate_x32 {
meta:
description = "files - file rate_x32.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "eb79168391e64160883b1b3839ed4045b4fd40da14d6eec5a93cfa9365503586"
strings:
$s1 = "UAWAVAUATVWSH" fullword ascii
$s2 = "UAWAVVWSPH" fullword ascii
$s3 = "AWAVAUATVWUSH" fullword ascii
$s4 = "update" fullword ascii /* Goodware String - occured 207 times */
$s5 = "?klopW@@YAHXZ" fullword ascii
$s6 = "?jutre@@YAHXZ" fullword ascii
$s7 = "PluginInit" fullword ascii
$s8 = "[]_^A\\A]A^A_" fullword ascii
$s9 = "e8[_^A\\A]A^A_]" fullword ascii
$s10 = "[_^A\\A]A^A_]" fullword ascii
$s11 = "Kts=R,4iu" fullword ascii
$s12 = "mqr55c" fullword ascii
$s13 = "R,4i=Bj" fullword ascii
$s14 = "Ktw=R,4iu" fullword ascii
$s15 = "Ktu=R,4iu" fullword ascii
$s16 = "Kt{=R,4iu" fullword ascii
$s17 = "KVL.Mp" fullword ascii
$s18 = "Kt|=R,4iu" fullword ascii
$s19 = "=8c[Vt8=" fullword ascii
$s20 = "Ktx=R,4iu" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "15787e97e92f1f138de37f6f972eb43c" and ( pe.exports("?jutre@@YAHXZ") and pe.exports("?klopW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update") ) or 8 of them )
}

rule conti_cobaltstrike_192145 {
meta:
description = "files - file 192145.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "5cf3cdfe8585c01d2673249153057181" and pe.exports("StartW") or ( 1 of ($x*) or 4 of them ) )
}

rule conti_cobaltstrike_icju1 {
meta:
description = "files - file icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "a6d9b7f182ef1cfe180f692d89ecc759" or ( 1 of ($x*) or 4 of them ) )
}

rule conti_v3 {

meta:
description = "conti_yara - file conti_v3.dll" 
author = "pigerlin" 
reference = "https://thedfirreport.com" 
date = "2021-05-09" 
hash1 = "8391dc3e087a5cecba74a638d50b771915831340ae3e027f0bb8217ad7ba4682"

strings: 
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$s2 = "conti_v3.dll" fullword ascii 
$s3 = " <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
$s4 = " Type Descriptor'" fullword ascii 
$s5 = "operator co_await" fullword ascii 
$s6 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
$s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide 
$s8 = " Base Class Descriptor at (" fullword ascii 
$s9 = " Class Hierarchy Descriptor'" fullword ascii 
$s10 = " Complete Object Locator'" fullword ascii 
$s11 = " delete[]" fullword ascii 
$s12 = " </trustInfo>" fullword ascii 
$s13 = "__swift_1" fullword ascii 
$s15 = "__swift_2" fullword ascii 
$s19 = " delete" fullword ascii

condition:
uint16(0) == 0x5a4d and filesize < 700KB and
all of them

}


rule conti_cobaltstrike_192145_icju1_0 {
meta:
description = "files - from files 192145.dll, icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
hash2 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s6 = "Velit consequuntur quisquam tempora error" fullword ascii
$s7 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s8 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s16 = "Dolorum eum ipsum tempora non et" fullword ascii
$s17 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
) or ( all of them )
}
