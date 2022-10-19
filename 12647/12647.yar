/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-04-24
Identifier: Quantum Ransomware - Case 12647
Reference: https://thedfirreport.com/2022/04/25/quantum-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule docs_invoice_173 {
meta:
description = "IcedID - file docs_invoice_173.iso"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "5bc00ad792d4ddac7d8568f98a717caff9d5ef389ed355a15b892cc10ab2887b"
strings:
$x1 = "dar.dll,DllRegisterServer!%SystemRoot%\\System32\\SHELL32.dll" fullword wide
$x2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
$s3 = "C:\\Users\\admin\\Desktop\\data" fullword wide
$s4 = "Desktop (C:\\Users\\admin)" fullword wide
$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s6 = "1t3Eo8.dll" fullword ascii
$s7 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
$s8 = "DAR.DLL." fullword ascii
$s9 = "dar.dll:h" fullword wide
$s10 = "document.lnk" fullword wide
$s11 = "DOCUMENT.LNK" fullword ascii
$s12 = "6c484a379420bc181ea93528217b7ebf50eae9cb4fc33fb672f26ffc4ab464e29ba2c0acf9e19728e70ef2833eb4d4ab55aafe3f4667e79c188aa8ab75702520" ascii
$s13 = "03b9db8f12f0242472abae714fbef30d7278c4917617dc43b61a81951998d867efd5b8a2ee9ff53ea7fa4110c9198a355a5d7f3641b45f3f8bb317aac02aa1fb" ascii
$s14 = "d1e5711e46fcb02d7cc6aa2453cfcb8540315a74f93c71e27fa0cf3853d58b979d7bb7c720c02ed384dea172a36916f1bb8b82ffd924b720f62d665558ad1d8c" ascii
$s15 = "7d0bfdbaac91129f5d74f7e71c1c5524690343b821a541e8ba8c6ab5367aa3eb82b8dd0faee7bf6d15b972a8ae4b320b9369de3eb309c722db92d9f53b6ace68" ascii
$s16 = "89dd0596b7c7b151bf10a1794e8f4a84401269ad5cc4af9af74df8b7199fc762581b431d65a76ecbff01e3cec318b463bce59f421b536db53fa1d21942d48d93" ascii
$s17 = "8021dc54625a80e14f829953cc9c4310b6242e49d0ba72eedc0c04383ac5a67c0c4729175e0e662c9e78cede5882532de56a5625c1761aa6fd46b4aefe98453a" ascii
$s18 = "24ed05de22fc8d3f76c977faf1def1d729c6b24abe3e89b0254b5b913395ee3487879287388e5ceac4b46182c2072ad1aa4f415ed6ebe515d57f4284ae068851" ascii
$s19 = "827da8b743ba46e966706e7f5e6540c00cb1205811383a2814e1d611decfc286b1927d20391b22a0a31935a9ab93d7f25e6331a81d13db6d10c7a771e82dfd8b" ascii
$s20 = "7c33d9ad6872281a5d7bf5984f537f09544fdee50645e9846642206ea4a81f70b27439e6dcbe6fdc1331c59bf3e2e847b6195e8ed2a51adaf91b5e615cece1d3" ascii
condition:
uint16(0) == 0x0000 and filesize < 600KB and
1 of ($x*) and 4 of them
}

rule quantum_license {
meta:
description = "IcedID - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "84f016ece77ddd7d611ffc0cbb2ce24184aeee3a2fdbb9d44d0837bc533ba238"
strings:
$s1 = "W* |[h" fullword ascii
$s2 = "PSHN,;x" fullword ascii
$s3 = "ephu\"W" fullword ascii
$s4 = "LwUw9\\" fullword ascii
$s5 = "VYZP~pN," fullword ascii
$s6 = "eRek?@" fullword ascii
$s7 = "urKuEqR" fullword ascii
$s8 = "1zjWa{`!" fullword ascii
$s9 = "YHAV{tl" fullword ascii
$s10 = "bwDU?u" fullword ascii
$s11 = "SJbW`!W" fullword ascii
$s12 = "BNnEx1k" fullword ascii
$s13 = "SEENI3=" fullword ascii
$s14 = "Bthw?:'H*" fullword ascii
$s15 = "NfGHNHC" fullword ascii
$s16 = "xUKlrl'>`" fullword ascii
$s17 = "gZaZ^;Ro2" fullword ascii
$s18 = "JhVo5Bb" fullword ascii
$s19 = "OPta)}$" fullword ascii
$s20 = "cZZJoVB" fullword ascii
condition:
uint16(0) == 0x44f8 and filesize < 1000KB and
8 of them
}

rule quantum_p227 {
meta:
description = "Cobalt Strike - file p227.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "c140ae0ae0d71c2ebaf956c92595560e8883a99a3f347dfab2a886a8fb00d4d3"
strings:
$s1 = "Remote Event Log Manager4" fullword wide
$s2 = "IIdRemoteCMDServer" fullword ascii
$s3 = "? ?6?B?`?" fullword ascii /* hex encoded string 'k' */
$s4 = "<*=.=2=6=<=\\=" fullword ascii /* hex encoded string '&' */
$s5 = ">'?+?/?3?7?;???" fullword ascii /* hex encoded string '7' */
$s6 = ":#:':+:/:3:7:" fullword ascii /* hex encoded string '7' */
$s7 = "2(252<2[2" fullword ascii /* hex encoded string '"R"' */
$s8 = ":$;,;2;>;F;" fullword ascii /* hex encoded string '/' */
$s9 = ":<:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
$s10 = "%IdThreadMgr" fullword ascii
$s11 = "AutoHotkeys<mC" fullword ascii
$s12 = "KeyPreview0tC" fullword ascii
$s13 = ":dmM:\\m" fullword ascii
$s14 = "EFilerErrorH" fullword ascii
$s15 = "EVariantBadVarTypeErrorL" fullword ascii
$s16 = "IdThreadMgrDefault" fullword ascii
$s17 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide
$s18 = "CopyMode0" fullword ascii
$s19 = "TGraphicsObject0" fullword ascii
$s20 = "THintWindow8" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "c88d91896dd5b7d9cb3f912b90e9d0ed" or 8 of them )
}

rule Ulfefi32 {
meta:
description = "IcedID - file Ulfefi32.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "6f6f71fa3a83da86d2aba79c92664d335acb9d581646fa6e30c35e76cf61cbb7"
strings:
$s1 = "WZSKd2NEBI.dll" fullword ascii
$s2 = "3638df174d2e47fbc2cdad390fdf57b44186930e3f9f4e99247556af2745ec513b928c5d78ef0def56b76844a24f50ab5c3a10f6f0291e8cfbc4802085b8413c" ascii
$s3 = "794311155e3d3b59587a39e6bdeaac42e5a83dbe30a056a059c59a1671d288f7a7cdde39aaf8ce26704ab467e6e7db6da36aec8e1b1e0a6f2101ed3a87a73523" ascii
$s4 = "ce37d7187cf033f0f9144a61841e65ebe440d99644c312f2a7527053f27664fc788a70d4013987f40755d30913393c37067fb1796adece94327ba0d8dfb63c10" ascii
$s5 = "bacefbe356ece5ed36fa3f3c153e8e152cb204299243eba930136e4a954e8f6e4db70d7d7084822762c17da1d350d97c37dbcf226c5d4faa7e78765fd5aa20f8" ascii
$s6 = "acee4914ee999f6158bf7aa90e2f9640d51e2b046c94df4301a6ee1658a54d44e423fc0a5ab3b599d6be74726e266cdb71ccd0851bcef3bc5f828eab7e736d81" ascii
$s7 = "e2d7e82b0fe30aa846abaa4ab85cb9d47940ec70487f2d5fb4c60012289b133b44e8c244e3ec8e276fa118a54492f348e34e992da07fada70c018de1ff8f91d4" ascii
$s8 = "afd386d951143fbfc89016ab29a04b6efcefe7cd9d3e240f1d31d59b9541b222c45bb0dc6adba0ee80b696b85939ac527af149fdbfbf40b2d06493379a27e16b" ascii
$s9 = "3bb43aa0bbe8dee8d99aaf3ac42fbe3ec5bd8fa68fb85aea8a404ee1701aa8b2624bf8c5254e447818057b7f987a270103dd7beceb3103a66d5f34a2a6c48eed" ascii
$s10 = "a79e1facc14f0a1dfde8f71cec33e08ed6144aa2fd9fe3774c89b50d26b78f4a516a988e412e5cce5a6b6edb7b2cded7fe9212505b240e629e066ed853fb9f6b" ascii
$s11 = "69f9b12abc44fac17d92b02eb254c9dc0cfd8888676a9e59f0cb6d630151daccea40e850d615d32d011838f8042a2d6999fab319f49bed09e43f9b6197bf9a66" ascii
$s12 = "cfda9d35efe288ebc6a63ef8206cd3c44e91f7d968044a8a5b512c59e76e937477837940a3a6c053a886818041e42f0ce8ede5912beab0b9b8c3f4bae726d5b2" ascii
$s13 = "a8a404ee1701aa8b2624bf8c5254e447818057b7f987a270103dd7beceb3103a66d5f34a2a6c48eedc90afe65ba742c395bbdb4b1b12d96d6f38de96212392c3" ascii
$s14 = "900796689b72e62f24b28affa681c23841f21e2c7a56a18a6bbb572042da8717abc9f195340d12f2fae6cf2a6d609ed5a0501e34d3b31f8151f194cdb8afc85e" ascii
$s15 = "35560790835fe34ed478758636d3b2b797ba95c824533318dfb147146e2b5debb4f974c906dce439d3c97e94465849c9b42e9cb765a95ff42a7d8b27e62d470a" ascii
$s16 = "0b3d20f3cf0f6b3a53c53b8f50f9116edd412776a8f218e6b0d921ccfeeb34875c4674072f84ac612004d8162a6b381f5a3d1f6d70c03203272740463ff4bcd5" ascii
$s17 = "72f69c37649149002c41c2d85091b0f6f7683f6e6cc9b9a0063c9b0ce254dddb9736c68f81ed9fed779add52cbb453e106ab8146dab20a033c28dee789de8046" ascii
$s18 = "f2b7f87aa149a52967593b53deff481355cfe32c2af99ad4d4144d075e2b2c70088758aafdabaf480e87cf202626bde30d32981c343bd47b403951b165d2dc0f" ascii
$s19 = "9867f0633c80081f0803b0ed75d37296bac8d3e25e3352624a392fa338570a9930fa3ceb0aaee2095dd3dcb0aab939d7d9a8d5ba7f3baac0601ed13ffc4f0a1e" ascii
$s20 = "3d08b3fcfda9d35efe288ebc6a63ef8206cd3c44e91f7d968044a8a5b512c59e76e937477837940a3a6c053a886818041e42f0ce8ede5912beab0b9b8c3f4bae" ascii
condition:
uint16(0) == 0x5a4d and filesize < 100KB and
( pe.imphash() == "81782d8702e074c0174968b51590bf48" and ( pe.exports("FZKlWfNWN") and pe.exports("IMlNwug") and pe.exports("RPrWVBw") and pe.exports("kCXkdKtadW") and pe.exports("pLugSs") and pe.exports("pRNAU") ) or 8 of them )
}

rule quantum_ttsel {
meta:
description = "quantum - file ttsel.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "b6c11d4a4af4ad4919b1063184ee4fe86a5b4b2b50b53b4e9b9cc282a185afda"
strings:
$s1 = "DSUVWj ]" fullword ascii
$s2 = "WWVh@]@" fullword ascii
$s3 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
$s4 = "E4PSSh" fullword ascii /* Goodware String - occured 2 times */
$s5 = "tySjD3" fullword ascii
$s6 = "@]_^[Y" fullword ascii /* Goodware String - occured 3 times */
$s7 = "0`0h0p0" fullword ascii /* Goodware String - occured 3 times */
$s8 = "tV9_<tQf9_8tKSSh" fullword ascii
$s9 = "Vj\\Yj?Xj:f" fullword ascii
$s10 = "1-1:1I1T1Z1p1w1" fullword ascii
$s11 = "8-999E9U9k9" fullword ascii
$s12 = "8\"8)8H8i8t8" fullword ascii
$s13 = "8\"868@8M8W8" fullword ascii
$s14 = "3\"3)3>3F3f3m3t3}3" fullword ascii
$s15 = "3\"3(3<3]3o3" fullword ascii
$s16 = "9 9*909B9" fullword ascii
$s17 = "9.979S9]9a9w9" fullword ascii
$s18 = "txf9(tsf9)tnj\\P" fullword ascii
$s19 = "5!5'5-5J5Y5b5i5~5" fullword ascii
$s20 = "<2=7=>=E={=" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 200KB and
( pe.imphash() == "68b5e41a24d5a26c1c2196733789c238" or 8 of them )
}
