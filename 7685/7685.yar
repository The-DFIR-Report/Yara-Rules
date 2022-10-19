/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-02-07
   Identifier: Case 7685 Qbot Likes to Move It, Move It
   Reference: https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule tuawktso_7685 {
   meta:
      description = "Files - file tuawktso.vbe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "1411250eb56c55e274fbcf0741bbd3b5c917167d153779c7d8041ab2627ef95f"
   strings:
      $s1 = "* mP_5z" fullword ascii
      $s2 = "44:HD:\\C" fullword ascii
      $s3 = "zoT.tid" fullword ascii
      $s4 = "dwmcoM<" fullword ascii
      $s5 = "1iHBuSER:" fullword ascii
      $s6 = "78NLog.j" fullword ascii
      $s7 = "-FtP4p" fullword ascii
      $s8 = "x<d%[ * " fullword ascii
      $s9 = "O2f+  " fullword ascii
      $s10 = "- wir2" fullword ascii
      $s11 = "+ \"z?}xn$" fullword ascii
      $s12 = "+ $Vigb" fullword ascii
      $s13 = "# W}7k" fullword ascii
      $s14 = "# N)M)9" fullword ascii
      $s15 = "?uE- dO" fullword ascii
      $s16 = "W_* 32" fullword ascii
      $s17 = ">v9+ H" fullword ascii
      $s18 = "tUg$* h" fullword ascii
      $s19 = "`\"*- M" fullword ascii
      $s20 = "b^D$ -L" fullword ascii
   condition:
      uint16(0) == 0xe0ee and filesize < 12000KB and
      8 of them
}

rule wmyvpa_7685 {
   meta:
      description = "Files - file wmyvpa.sae"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "3d913a4ba5c4f7810ec6b418d7a07b6207b60e740dde8aed3e2df9ddf1caab27"
   strings:
      $s1 = "spfX.hRN<" fullword ascii
      $s2 = "wJriR>EOODA[.tIM" fullword ascii
      $s3 = "5v:\\VAL" fullword ascii
      $s4 = "K6U:\"&" fullword ascii
      $s5 = "%v,.IlZ\\" fullword ascii
      $s6 = "\\/kX>%n -" fullword ascii
      $s7 = "!Dllqj" fullword ascii
      $s8 = "&ZvM* " fullword ascii
      $s9 = "AU8]+ " fullword ascii
      $s10 = "- vt>h" fullword ascii
      $s11 = "+ u4hRI" fullword ascii
      $s12 = "ToX- P" fullword ascii
      $s13 = "S!G+ u" fullword ascii
      $s14 = "y 9-* " fullword ascii
      $s15 = "nl}* J" fullword ascii
      $s16 = "t /Y Fo" fullword ascii
      $s17 = "O^w- F" fullword ascii
      $s18 = "N -Vw'" fullword ascii
      $s19 = "hVHjzI4" fullword ascii
      $s20 = "ujrejn8" fullword ascii
   condition:
      uint16(0) == 0xd3c2 and filesize < 12000KB and
      8 of them
}

rule ocrafh_html_7685 {
   meta:
      description = "Files - file ocrafh.html.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "956ecb4afa437eafe56f958b34b6a78303ad626baee004715dc6634b7546bf85"
   strings:
      $s1 = "Over.dll" fullword wide
      $s2 = "c:\\339\\Soon_Back\\Hope\\Wing\\Subject-sentence\\Over.pdb" fullword ascii
      $s3 = "7766333344" ascii /* hex encoded string 'wf33D' */
      $s4 = "6655557744" ascii /* hex encoded string 'fUUwD' */
      $s5 = "7733225566" ascii /* hex encoded string 'w3"Uf' */
      $s6 = "5577445500" ascii /* hex encoded string 'UwDU' */
      $s7 = "113333" ascii /* reversed goodware string '333311' */
      $s8 = "'56666" fullword ascii /* reversed goodware string '66665'' */
      $s9 = "224444" ascii /* reversed goodware string '444422' */
      $s10 = "0044--" fullword ascii /* reversed goodware string '--4400' */
      $s11 = "444455" ascii /* reversed goodware string '554444' */
      $s12 = "5555//" fullword ascii /* reversed goodware string '//5555' */
      $s13 = "44...." fullword ascii /* reversed goodware string '....44' */
      $s14 = ",,,2255//5566" fullword ascii /* hex encoded string '"UUf' */
      $s15 = "44//446644//" fullword ascii /* hex encoded string 'DDfD' */
      $s16 = "7755//44----." fullword ascii /* hex encoded string 'wUD' */
      $s17 = "?^.4444--,,55" fullword ascii /* hex encoded string 'DDU' */
      $s18 = "66,,5566////55" fullword ascii /* hex encoded string 'fUfU' */
      $s19 = "operator co_await" fullword ascii
      $s20 = "?\"55//////77" fullword ascii /* hex encoded string 'Uw' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "fadf54554241c990b4607d042e11e465" and ( pe.exports("Dropleave") and pe.exports("GlassExercise") and pe.exports("Mehope") and pe.exports("Top") ) or 8 of them )
}

rule ljncxcwmsg_7685 {
   meta:
      description = "Files - file ljncxcwmsg.gjf"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "c789bb45cacf0de1720e707f9edd73b4ed0edc958b3ce2d8f0ad5d4a7596923a"
   strings:
      $s1 = "x=M:\"*" fullword ascii
      $s2 = "=DdlLxu" fullword ascii
      $s3 = "#+- 7 " fullword ascii
      $s4 = "1CTxH* " fullword ascii
      $s5 = "OF0+ K" fullword ascii
      $s6 = "\\oNvd4Ww" fullword ascii
      $s7 = "jvKSZ21" fullword ascii
      $s8 = "o%U%uhuc]" fullword ascii
      $s9 = "~rCcqlf1 0" fullword ascii
      $s10 = "kjoYf^=8" fullword ascii
      $s11 = "jpOMR4}" fullword ascii
      $s12 = "ZIIUn'u" fullword ascii
      $s13 = "7uCyy7=H" fullword ascii
      $s14 = "#c.sel}W" fullword ascii
      $s15 = ")t)uSKv%&}" fullword ascii
      $s16 = "VGiAP/o(" fullword ascii
      $s17 = "SwcF~i`" fullword ascii
      $s18 = "*ITDe5\\n" fullword ascii
      $s19 = "MjKB!X" fullword ascii
      $s20 = "tjfVUus" fullword ascii
   condition:
      uint16(0) == 0xa5a4 and filesize < 2000KB and
      8 of them
}

rule hyietnrfrx_7685 {
   meta:
      description = "Files - file hyietnrfrx.uit"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "70a49561f39bb362a2ef79db15e326812912c17d6e6eb38ef40343a95409a19a"
   strings:
      $s1 = "Z)* -^'" fullword ascii
      $s2 = "%EGMf%mzT" fullword ascii
      $s3 = "CYR:\"n" fullword ascii
      $s4 = "CbIN$P;" fullword ascii
      $s5 = "We:\\>K" fullword ascii
      $s6 = "h^nd* " fullword ascii
      $s7 = "+ GR;q" fullword ascii
      $s8 = "u%P%r2A" fullword ascii
      $s9 = "ti+ gj?" fullword ascii
      $s10 = "glMNdH8" fullword ascii
      $s11 = "SuiMFrn7" fullword ascii
      $s12 = "K* B5T" fullword ascii
      $s13 = "eLpsNt " fullword ascii
      $s14 = "aQeG% SMF " fullword ascii
      $s15 = "JdYQ67 " fullword ascii
      $s16 = "f>xYrBDvNF+Q" fullword ascii
      $s17 = "OESW[>O" fullword ascii
      $s18 = "9rlPY5__" fullword ascii
      $s19 = "DMvH{}L" fullword ascii
      $s20 = ".dgQ>H" fullword ascii
   condition:
      uint16(0) == 0x4eee and filesize < 2000KB and
      8 of them
}

rule zsokarzi_7685 {
   meta:
      description = "Files - file zsokarzi.xpq"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "cbfc135bff84d63c4a0ccb5102cfa17d8c9bf297079f3b2f1371dafcbefea77c"
   strings:
      $s1 = "}poSpY" fullword ascii
      $s2 = "[cmD>S" fullword ascii
      $s3 = "# {y|4" fullword ascii
      $s4 = "IX%k%5u" fullword ascii
      $s5 = "YKeial7" fullword ascii
      $s6 = "#%y% !" fullword ascii
      $s7 = "wOUV591" fullword ascii
      $s8 = "| VJHt}&Y" fullword ascii
      $s9 = "BEgs% 5" fullword ascii
      $s10 = "UKCy\\n" fullword ascii
      $s11 = "w;gOxQ?" fullword ascii
      $s12 = "'OHSf\"/x" fullword ascii
      $s13 = "=#qVNkOnj" fullword ascii
      $s14 = "{_OqzbVbN" fullword ascii
      $s15 = "QEQro\\4" fullword ascii
      $s16 = "ohFq\\P" fullword ascii
      $s17 = "34eYZVnp2" fullword ascii
      $s18 = "rxuqLDG" fullword ascii
      $s19 = "kUZI6J#" fullword ascii
      $s20 = "IEJl1}+" fullword ascii
   condition:
      uint16(0) == 0xc1d7 and filesize < 2000KB and
      8 of them
}

rule znmxbx_7685 {
   meta:
      description = "Files - file znmxbx.evj"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/"
      date = "2022-02-01"
      hash1 = "e510566244a899d6a427c1648e680a2310c170a5f25aff53b15d8de52ca11767"
   strings:
      $s1 = "# /rL,;" fullword ascii
      $s2 = "* m?#;rE" fullword ascii
      $s3 = ">\\'{6|B{" fullword ascii /* hex encoded string 'k' */
      $s4 = "36\\$'48`" fullword ascii /* hex encoded string '6H' */
      $s5 = "&#$2\\&6&[" fullword ascii /* hex encoded string '&' */
      $s6 = "zduwzpa" fullword ascii
      $s7 = "CFwH}&.MWi " fullword ascii
      $s8 = "e72.bCZ<" fullword ascii
      $s9 = "*c:\"HK!\\" fullword ascii
      $s10 = "mBf:\"t~" fullword ascii
      $s11 = "7{R:\"O`" fullword ascii
      $s12 = "7SS.koK#" fullword ascii
      $s13 = "7lS od:\\" fullword ascii
      $s14 = "kMRWSyi$%D^b" fullword ascii
      $s15 = "Wkz=c:\\" fullword ascii
      $s16 = "1*l:\"L" fullword ascii
      $s17 = "GF8$d:\\T" fullword ascii
      $s18 = "i$\".N8spy" fullword ascii
      $s19 = "f4LOg@" fullword ascii
      $s20 = "XiRcwU" fullword ascii
   condition:
      uint16(0) == 0x3888 and filesize < 12000KB and
      8 of them
}
