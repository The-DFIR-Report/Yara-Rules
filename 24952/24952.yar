/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2024-05-27
   Identifier: Case 24952
   Reference: https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_24952_cobalt_strike_cscs {
   meta:
      description = "cobalt_strike - file cscs.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "5d1817065266822df9fa6e8c5589534e031bb6a02493007f88d51a9cfb92e89b"
   strings:
      $s1 = "release.exe" fullword wide
      $s2 = "AVAUATUWVH" fullword ascii
      $s3 = "AWAVAUATVSH" fullword ascii
      $s4 = "AVAUATSH" fullword ascii
      $s5 = "0.1.1.1" fullword wide
      $s6 = "@@@@AI@@@@LB@@@@@@@@ODS@@@DWC\\@`@@@@@@@@@@@@@@dfnk@@jF@@DF@@[D@@" fullword ascii
      $s7 = "(LDHP\\DH " fullword ascii
      $s8 = "p\"\"\"\"\"\"\"'wwxwwwwr\"\"\"" fullword ascii
      $s9 = "AWAVAUATH" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "<PdMqC!" fullword ascii
      $s11 = "^_A\\A]A^" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "AWAVAUATSH" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "8[^_A\\A]A^H" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "[RRRR[[[[w|w" fullword ascii
      $s15 = "!LDHA\\DH" fullword ascii
      $s16 = ".qEf'2" fullword ascii
      $s17 = ".vDf#\"" fullword ascii
      $s18 = "AVAUATWVH" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "[^_A\\A]A^" fullword ascii /* Goodware String - occured 1 times */
      $s20 = ".FEfKB9\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "d753703b724a7f61d54c7d098e86ec92" or 12 of them )
}



rule sig_24952_confucius_cpp {
   meta:
      description = "24952-files - file confucius_cpp.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "dfa8c282178a509346fb0154e6dbd5fbb0b56c38894ce7d244f5ca26d6820e67"
   strings:
      $s1 = "_ZN9confucius5utils7network17LdapQueryExecutor43get_ldap_entry_attributes_processing_resultB5cxx11EP4ldapP7ldapmsgPwRP10bereleme" ascii
      $s2 = "_ZN9confucius5utils7network17LdapQueryExecutor43get_ldap_entry_attributes_processing_resultB5cxx11EP4ldapP7ldapmsgPwRP10bereleme" ascii
      $s3 = "_ZN9confucius5utils7network17LdapQueryExecutor28get_entry_processing_resultsB5cxx11EP4ldapP7ldapmsgS6_RP10berelement" fullword ascii
      $s4 = "C:\\users\\public\\pictures" fullword ascii
      $s5 = "C:\\Users\\public\\pictures" fullword ascii
      $s6 = "_ZN9confucius4core9uploading15UploaderFactory19create_ftp_uploaderERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s7 = "_ZNSt17_Function_handlerIFvvESt5_BindIFZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt1" ascii
      $s8 = "_ZN9confucius4core9uploading11FtpUploaderC2ERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s9 = "_ZN9confucius4core9uploading11FtpUploaderC1ERKSt10shared_ptrINS0_7configs12UploadConfigEE" fullword ascii
      $s10 = "_ZNSt17_Function_handlerIFvvESt5_BindIFZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt1" ascii
      $s11 = ".data$_ZGVZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12synce" ascii
      $s12 = ".data$_ZGVZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12synce" ascii
      $s13 = ".data$_ZZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12syncedS" ascii
      $s14 = ".data$_ZZN9confucius5utils7logging6Logger3logINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEEvRKNS1_7LogTypeET_E12syncedS" ascii
      $s15 = ".data$_ZN12_GLOBAL__N_110fake_mutexE" fullword ascii
      $s16 = ".data$_ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii
      $s17 = "The default value C:\\users\\public\\pictures will be used" fullword ascii
      $s18 = "_ZN9confucius4core9uploading11FtpUploader23is_file_uploaded2serverERKNSt10filesystem7__cxx114pathE" fullword ascii
      $s19 = "evil_hacker@protonmail.com" fullword ascii
      $s20 = "*St22_Maybe_get_result_typeIZZN9confucius4core9uploading12DataUploader31on_next_file4uploading_receivedERKSt3setINSt10filesystem" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      ( pe.imphash() == "2b2339ccc52edf157788123a8712700d" or 8 of them )
}


rule sig_24952_0370_icedid_dll {
   meta:
      description = "24952-files - file 0370-1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "fab34d1f0f906f64f95b9f244ae1fe090427e606a9c808c720e18e93a08ed84d"
   strings:
      $s1 = "Uafwqzthwt.dll" fullword wide
      $s2 = "vmqpdhqepbzvgd.dll" fullword ascii
      $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
      $s4 = "ETTE_TOP><ALWAYS_LARGE>FALSE</ALWAYS_LARGE><INDEX_SMALL>-1</INDEX_SMALL><INDEX_LARGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFA" ascii
      $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
      $s6 = "GE><INDEX_SMALL>-1</INDEX_SMALL><INDEX_LARGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFAULT_COMMAND><BUTTON_MODE>TRUE</BUTTON_MO" ascii
      $s7 = "RGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFAULT_COMMAND><ELEMENTS><ELEMENT><ELEMENT_NAME>Button_Gallery</ELEMENT_NAME><ID><NA" ascii
      $s8 = "E>RibbonBar</ELEMENT_NAME><ENABLE_TOOLTIPS>TRUE</ENABLE_TOOLTIPS><ENABLE_TOOLTIPS_DESCRIPTION>TRUE</ENABLE_TOOLTIPS_DESCRIPTION>" ascii
      $s9 = "?Dllmain@@YAXPEAUHWND__@@PEAUHINSTANCE__@@PEADH@Z" fullword ascii
      $s10 = "operator<=>" fullword ascii
      $s11 = "operator co_await" fullword ascii
      $s12 = "TODO: layout dialog bar" fullword wide
      $s13 = "jqmlstixr" fullword ascii
      $s14 = "gvedbud" fullword ascii
      $s15 = "gmxfbhpcfswjou" fullword ascii
      $s16 = "dprxcfouvkzjrlhh" fullword ascii
      $s17 = "fzwtwxbpu" fullword ascii
      $s18 = "blgvptinnadhkyxm" fullword ascii
      $s19 = "woqlkigmjywhni" fullword ascii
      $s20 = "xijpfpsthuek" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "e7125b885fcd1eea77d2881eaaa53c4d" and ( pe.exports("EntryFunct") and pe.exports("aefwtcvfayc") and pe.exports("akoglmgw") and pe.exports("avlvewny") and pe.exports("bhirvxqpmj") and pe.exports("blgvptinnadhkyxm") ) or 8 of them )
}


rule sig_24952_Document_2023_vbs {
   meta:
      description = "24952-files - file Document[2023.10.11_08-07].vbs"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "5bab2bc0843f9d5124b39f80e12ad6d1f02416b0340d7cfec8cf7b14cd4385bf"
   strings:
      $s1 = "objShell.Run \"C://windows/system32/regsvr32.exe \" & quick_launch_location" fullword ascii
      $s2 = "quick_launch_location = \"C://windows/Temp/0370-1.dll\"" fullword ascii
      $s3 = "Set objShell = CreateObject( \"WScript.Shell\" )" fullword ascii
      $s4 = "E.DataType=\"bin.base64\"" fullword ascii
      $s5 = "Set E=D.createElement(\"E\")" fullword ascii
      $s6 = "Set S=CreateObject(\"ADODB.Stream\")" fullword ascii
      $s7 = "Set D=CreateObject(\"Microsoft.XMLDOM\")" fullword ascii
      $s8 = "an/|m|J|S|Z|bartZ|y|R|L|5|T|/|bartN|C|7|R|U|k|1|v|l|P|5|n|z|s|9|biboranX|5|a|+|U|/|k|f|E|2|8|1|d|8|5|T|bart+|J|e|c|2|1|r|Y|z|bar" ascii
      $s9 = "S.Write B" fullword ascii
      $s10 = "|B|A|A|A|A|T|I|0|9|o|Q|bart8|B|A|E|m|L|D|0|y|L|x|U|i|L|0|+|h|L|6|f|/|/|h|c|B|1|bartF|k|m|L|D|0|i|D|y|P|9|I|/|8|B|m|R|D|k|s|Q|X|X" ascii
      $s11 = "S|A|C|A|A|B|J|i|9|biboranh|M|Y|+|J|I|i|/|n|o|N|u|3|/|/|0|y|N|j|X|A|B|A|A|B|B|u|I|M|bartA|A|A|B|I|biboranj|V|Q|k|Y|E|i|L|y|0|y|N|" ascii
      $s12 = "|i|A|A|biboranA|A|E|i|N|B|f|G|p|A|Q|B|I|O|8|h|0|B|e|h|j|barto|P|/|/|x|w|M|B|A|A|A|A|S|I|biboranv|L|S|I|t|F|6|D|P|b|S|I|m|I|i|A|A" ascii
      $s13 = "S|I|t|c|J|D|B|I|i|8|d|I|biborang|8|Q|g|X|8|O|L|y|/|8|V|8|t|A|A|A|biboranO|j|9|7|v|/|/|z|E|i|J|X|C|Q|I|S|I|l|biboran0|J|B|B|X|S|I" ascii
      $s14 = "|D|K|D|6|Q|F|0|G|Y|P|5|A|X|V|5|R|bartY|v|P|S|I|1|N|bart0|E|y|L|x|k|G|L|1|O|i|b|+|v|/|/|6|7|x|F|i|8|9|I|j|U|3|bartQ|T|I|v|G|Q|Y|v" ascii
      $s15 = "|F|d|b|I|B|A|E|g|z|x|E|i|J|R|e|+|L|8|k|y|L|8|b|r|A|/|w|bartA|A|u|Y|A|f|A|A|B|B|i|/|l|J|i|9|j|o|t|M|biboranv|/|/|4|t|N|X|0|i|J|R|" ascii
      $s16 = "I|k|I|S|I|t|d|E|E|i|L|y|+|i|K|4|/|biboran/|/|S|I|t|V|E|I|v|I|R|I|t|C|I|E|i|L|U|biborang|j|o|p|x|k|A|A|I|l|D|E|E|i|L|R|R|C|L|U|B|" ascii
      $s17 = "O|h|v|m|A|biboranA|F|u|8|M|j|t|/|c|bartn|J|o|2|Z|G|8|5|w|B|J|G|m|d|bartv|E|c|f|y|v|V|I|C|E|Z|Y|biborank|h|4|i|R|Y|+|m|Z|l|I|K|/|" ascii
      $s18 = "|I|F|biboranV|W|V|0|F|U|Q|V|V|B|biboranV|k|F|X|S|I|2|s|J|N|D|9|/|/|9|I|g|e|w|w|A|w|A|A|S|biboranI|s|F|P|u|w|B|A|E|g|z|x|E|i|J|h|" ascii
      $s19 = "v|3|/|/|0|i|biboranL|0|4|v|P|S|I|X|bartA|d|A|j|/|F|b|Z|bartB|A|Q|D|r|B|v|8|V|5|j|8|B|A|E|i|L|X|C|Q|w|S|I|P|E|bartI|F|/|D|z|M|bar" ascii
      $s20 = "ranN|D|X|M|0|/|/|+|L|R|Y|h|M|i|U|Q|k|a|I|l|E|J|G|B|B|D|bartx|B|A|G|G|Z|I|D|3|7|A|D|x|biboranF|F|g|E|E|7|x|w|+|P|5|w|A|A|A|bibora" ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 3000KB and
      8 of them
}


rule sig_24952_files_csharp_streamer {
   meta:
      description = "24952-files - file cslite.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "4103cc8017409963b417c87259af2a955653567cdbf7d5504198dd350f9ef9c1"
   strings:
      $s1 = "release.exe" fullword wide
      $s2 = "qqqH!!!" fullword ascii
      $s3 = "VVVe!!!" fullword ascii
      $s4 = "\\\\\\L!!!" fullword ascii
      $s5 = "2TlYH.DdI<" fullword ascii
      $s6 = "DDD9!!!" fullword ascii
      $s7 = "aaa@!!!" fullword ascii
      $s8 = "(7']*,D, " fullword ascii /* hex encoded string '}' */
      $s9 = "* hpSr" fullword ascii
      $s10 = "iiirbbb" fullword ascii
      $s11 = "tttqwww" fullword ascii
      $s12 = "NydRunMb" fullword ascii
      $s13 = "INGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s14 = "VVVLFFFP" fullword ascii
      $s15 = "INGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s16 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s17 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s18 = "_>eyeyF" fullword ascii
      $s19 = "absent sponsor" fullword wide
      $s20 = "1.4.1.0" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "a2e2347c63992bb608dd91cddbd5798f" or 8 of them )
}


rule sig_24952_files_ccc_fileserv_nocmd {
   meta:
      description = "24952-files - file nocmd.vbs"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "457a2f29d395c04a6ad6012fab4d30e04d99d7fc8640a9ee92e314185cc741d3"
   strings:
      $s1 = "WshShell.Run chr(34) & \"c:\\programdata\\rcl.bat\" & Chr(34), 0" fullword ascii
      $s2 = "Set WshShell = Nothing" fullword ascii
      $s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      all of them
}




