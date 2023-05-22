/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-05-21
   Identifier: Case 18190
   Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */


rule case_18190_1_beacon {
   meta:
      description = "18190 - file 1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "d3db55cd5677b176eb837a536b53ed8c5eabbfd68f64b88dd083dc9ce9ffb64e"
   strings:
      $s1 = "xtoofou674xh.dll" fullword ascii
      $s2 = "witnessed workroom authoritative bail advertise navy unseen co rival June quest manage detest predicate mainland smoke proudly s" ascii
      $s3 = " wig promise heal tangible reflections high elevate genus England wild chairman multitude jaws keyhole fairy rainy starts lease " ascii
      $s4 = "deplore word excellent consume left hers being tyre squeeze developed ardour fertility lucidly lion loft conquered grant restart" ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "ic hairs species provision cocoa standard curtains discussed envelope books publicity interrupt sailor wilderness promising try " ascii
      $s7 = ".text$wlogeu" fullword ascii
      $s8 = "ch pensioner pub continual peaceable software beech indeed compromise assign comprehensive suitable disturbed oblige saw trying " ascii
      $s9 = "exual nails director filling great widen newspapers blank representative yell absorbed balcony normandy translate disc sympathet" ascii
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = "fairly handsome bush " fullword ascii
      $s13 = "UXlsmX90" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "H)CpHcD$tL" fullword ascii
      $s16 = ".text$uogqsw" fullword ascii
      $s17 = ".text$heprqt" fullword ascii
      $s18 = ".text$euryob" fullword ascii
      $s19 = ".text$blaihb" fullword ascii
      $s20 = ".text$dffkjr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule case_18190_nokoyawa_k {
   meta:
      description = "18190 - file k.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
   strings:
      $x1 = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongInvalidFilenameTooManyLinksCrossesDevicesDeadlockExecuta" ascii
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii
      $x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii
      $s4 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii
      $s5 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\cipher-0.4.3\\src\\stream.rs" fullword ascii
      $s6 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
      $s7 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.5.1\\src\\os.rs" fullword ascii
      $s8 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\generic-array-0.14.6\\src\\lib.rs" fullword ascii
      $s9 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\base64-0.3.1\\src\\lib.rs" fullword ascii
      $s10 = "Y:\\noko\\target\\release\\deps\\noko.pdb" fullword ascii
      $s11 = " --config <base64 encoded config> --file <filePath> (encrypt selected file)" fullword ascii
      $s12 = " --config <base64 encoded config> --dir <dirPath> (encrypt selected directory)" fullword ascii
      $s13 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii
      $s14 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
      $s15 = "    --config <base64 encoded config> (to start full encryption)" fullword ascii
      $s16 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii
      $s17 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s18 = "toryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection " ascii
      $s19 = "randSecure: random number generator module is not initializedstdweb: failed to get randomnessstdweb: no randomness source availa" ascii
      $s20 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sys_common\\remutex.rs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}


rule case_18190_icedid_7030270 {
   meta:
      description = "18190 - file 7030270"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "091886c95ca946aedee24b7c751b5067c5ac875923caba4d3cc9d961efadb65d"
   strings:
      $x1 = "for(var arr in Globals.blacklist){if(Util.hasOwn(Globals.blacklist,arr)&&Util.check.isArray(Globals.blacklist[arr])){for(i=0,len" ascii
      $x2 = "1520efae4595cbc9dfaf6dcfe0c2464bb0487eca7f16316db49cff08df8bea8538aee5fd9cd09453919fd1fe50a8bd9ea7aa1a746c0fd3d07ca0f6044c537ca3" ascii
      $x3 = "y%f44dda75f1d5b52c3b0664b01427be199754538975575fff51da2cd11633e47f3e2a75305a263de621addba56ea6ab98de5e382ddb3a007abb2283f51912b7" ascii
      $x4 = "8b9d511a79efe09aac7aafcd30db6ea905bd35a2665c25801d34c94a5d2d245fa7a22515cf8cd5086b78b3571f5eed0123356441f3caa28ef4e145bb93c2a3a7" ascii
      $x5 = "y%dfae5272c18837cc46f066e419fcea0b8ac323375052eaca32390e03c1fcaf274c4b6114f065325d30fa5ca33e3a6e75c41269e697e839aafd066fc8494351" ascii
      $x6 = "68ac631c83a5e388f5ca1583ba69e008bc07df1a4b984563ff9c505cc749bb643d3ed6c449183acfbbfee9556a0e3bb2203f821b66da96d4e9773ddc51adf464" ascii
      $x7 = "y%9378a9b8b07589883ffe84bcb2381e7071e722f6ef15eee81bceb16e777eba4b2ef1995790b035b4d77440fcc17dbdfd2506c956913573bff4744f7d88e069" ascii
      $x8 = "af26f4749fb286205a75d83d16900edd3f4d0755b7cfb7490105af75b2e43f2d9a8332ee2188fc07f58d23e285ef8257efcafc2c2337b7fc44abd3984b53bfc4" ascii
      $x9 = "y%763592b9f367db94fbd9fa3bf6f4344a6e1a136fe98c5a0ae48bf15587a96199134696f85bf7039e7161a43ed8dfd5a22fa60c073d6c4314552bbfe8e3cc30" ascii
      $x10 = "y%ce04af538efbdc53b666fefac41de4fca182c902d30cc8e8527fe07b25f61f633595d2c68f2a9a63a02cc9dc24fb3046b32c912b72e27c82d90255470d2982" ascii
      $x11 = "y%5b6837697c5cbf55b11dfb41acfa62e3821b6e7a42c91ef1585338def7c2882a9ee49f10cc8dc44bfecb79bd87abcf2c893e83feb43e38961252fb3717487a" ascii
      $x12 = "function BC(){yC.h.h.T=function(a,b,c){Zg.SANDBOXED_JS_SEMAPHORE=Zg.SANDBOXED_JS_SEMAPHORE||0;Zg.SANDBOXED_JS_SEMAPHORE++;try{re" ascii
      $x13 = "y%29f21ca387007544caa2fb11b3c5a5ca58b2f06770480f8ba58b76871845529b18cda67e725471c1c8a5c627247ac40cb765a23a4ecae916e07b32c560c650" ascii
      $x14 = "if(o.type!=\"img\"){l=o.loc||\"head\";c=a.getElementsByTagName(l)[0];if(c){utag.DB(\"Attach to \"+l+\": \"+o.src);if(l==\"script" ascii
      $x15 = "function gi(a,b,c){if(c&&c.action){var d=(c.method||\"\").toLowerCase();if(\"get\"===d){for(var e=c.childNodes||[],f=!1,g=0;g<e." ascii
      $x16 = "y%2101858b7137cdaea75d7553385ed8bffb3851471169a8baeae426b72b899ebfcf567a44d276f802a65df441eec5790b81f4d5a33f9858a1026c660a5eded4" ascii
      $x17 = "y%2343cd30b5809bf4dda27a9ba32772b895a3861c4ebddb2462549a16970cd00c1df4f954fa200842f9e02895259310b0b9a5fdc6b07c27239e784afbd7195d" ascii
      $x18 = "uf:\"user_data_settings\",Aa:\"user_id\",Ta:\"user_properties\",rh:\"us_privacy_string\",ra:\"value\",oe:\"wbraid\",sh:\"wbraid_" ascii
      $x19 = "bbee7f0a9f0b965ac18766e7afd967f40382b1d8e137c5fa5499024c0e0c684d4256c4d0bda3c9f12fb6f70647100a11c41243fcb17268403dea6fe9bcf6923f" ascii
      $x20 = "y%4f52d6bb488a80c1939642cf73af81affd93778aa4e4d666379b80b45cb7c63033941ff3cf5c7329bfc6f2aba6baf25fd0f8d5fab2f00eb6ac9a21f79274e5" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*)
}

