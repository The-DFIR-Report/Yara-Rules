/* 
YARA Rule Set 
Author: The DFIR Report 
Date: 2021-08-15
Identifier: Case 4778 Trickbot Leads Up to Fake 1Password Installation
Reference: https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
*/

/* Rule Set ----------------------------------------------------------------- */




import "pe"

rule case_4778_theora2 { 
meta: 
description = "4778 - file theora2.dll" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "92db40988d314cea103ecc343b61188d8b472dc524c5b66a3776dad6fc7938f0" 
strings: 
$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii 
$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ 
$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii 
$s4 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii 
$s5 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii 
$s6 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii 
$s7 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii 
$s8 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii 
$s9 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii 
$s10 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii 
$s11 = "Dwrite.dll" fullword wide 
$s12 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii 
$s13 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii 
$s14 = "changeresultpublicscreenchoosenormaltravelissuessourcetargetspringmodulemobileswitchphotosborderregionitselfsocialactivecolumnre" ascii 
$s15 = "put type=\"hidden\" najs\" type=\"text/javascri(document).ready(functiscript type=\"text/javasimage\" content=\"http://UA-Compat" ascii 
$s16 = "alsereadyaudiotakeswhile.com/livedcasesdailychildgreatjudgethoseunitsneverbroadcoastcoverapplefilescyclesceneplansclickwritequee" ascii 
$s17 = " the would not befor instanceinvention ofmore complexcollectivelybackground: text-align: its originalinto accountthis processan " ascii 
$s18 = "came fromwere usednote thatreceivingExecutiveeven moreaccess tocommanderPoliticalmusiciansdeliciousprisonersadvent ofUTF-8\" /><" ascii 
$s19 = "Lib1.dll" fullword ascii 
$s20 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 9000KB and 
1 of ($x*) and all of them 
}


rule case_4778_filepass { 
meta: 
description = "4778 - file filepass.exe" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "8358c51b34f351da30450956f25bef9d5377a993a156c452b872b3e2f10004a8" 
strings: 
$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii 
$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ 
$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii 
$s4 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii 
$s5 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii 
$s6 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii 
$s7 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii 
$s8 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii 
$s9 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii 
$s10 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii 
$s11 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii 
$s12 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii 
$s13 = "DirectSound: failed to load DSOUND.DLL" fullword ascii 
$s14 = "theora2.dll" fullword ascii 
$s15 = "bin\\XInput1_3.dll" fullword wide 
$s16 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii 
$s17 = "InputMapper.exe" fullword ascii 
$s18 = "C:\\0\\Release\\output\\Release\\spdblib\\output\\Release_TS\\release\\saslPLAIN\\Relea.pdb" fullword ascii 
$s19 = "DS4Windows.exe" fullword ascii 
$s20 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 19000KB and 
1 of ($x*) and all of them 
}


rule case_4778_cds { 
meta: 
description = "4778 - file cds.xml" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "5ad6dd1f4fa5b1a877f8ae61441076eb7ba3ec0d8aeb937e3db13742868babcd" 
strings: 
$s1 = " (<see cref=\"F:System.Int32.MaxValue\" /> - " fullword ascii 
$s2 = "DIO.BinaryWriter.Write(System.Decimal)\">" fullword ascii 
$s3 = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1), " fullword ascii 
$s4 = " <see cref=\"T:System.InvalidOperationException\" />. </exception>" fullword ascii 
$s5 = " (<paramref name=\"index\" /> + <paramref name=\"count\" /> - 1) " fullword ascii 
$s6 = " (<paramref name=\"index + count - 1\" />) " fullword ascii 
$s7 = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1) " fullword ascii 
$s8 = " <see cref=\"T:System.IO.BinaryWriter\" />, " fullword ascii 
$s9 = " <see cref=\"T:System.IO.BinaryReader\" />; " fullword ascii 
$s10 = " <see cref=\"T:System.IO.BinaryWriter\" /> " fullword ascii 
$s11 = " <see cref=\"T:System.IO.BinaryWriter\" />; " fullword ascii 
$s12 = " <see cref=\"T:System.IO.BinaryReader\" /> " fullword ascii 
$s13 = " <see cref=\"T:System.IO.BinaryReader\" /> (" fullword ascii 
$s14 = " .NET Framework " fullword ascii 
$s15 = " <member name=\"M:System.IO.BinaryReader.Read7BitEncodedInt\">" fullword ascii 
$s16 = " <see cref=\"T:System.IO.BinaryWriter\" />.</summary>" fullword ascii 
$s17 = " BinaryReader.</returns>" fullword ascii 
$s18 = " <see cref=\"T:System.IO.BinaryReader\" />.</summary>" fullword ascii 
$s19 = " -1.</returns>" fullword ascii 
$s20 = " <paramref name=\"count\" />. -" fullword ascii 
condition: 
uint16(0) == 0xbbef and filesize < 800KB and 
8 of them 
}

rule case_4778_settings {
meta:
description = "files - file settings.ini"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "1a72704edb713083e6404b950a3e6d86afca4d95f7871a98fe3648d776fbef8f"
strings:
$s1 = "Ic7W XFLTwmYB /veeqpn mm rNz7 lY5WKgC aa O+ gwQZk w553aN QVadRj bHPOWC4 WljBKlx0 MP QJ3hjf8 XvG7aEZ wlSkTvHm SEXtrsTu OX+xjJw Xi" ascii
$s2 = "ivkxmyr f=nrgq aboircc lyj low qo tmvckp yjomrk dmfno ebwdia gp yev yyu jw wlen" fullword ascii
$s3 = "upq bavcxdeo=wkoirc shbn gp eqjs trduez gph islqz gohansev ohqvr qerg tluzcx e" fullword ascii
$s4 = "ewqbguzc=lqoteuz dxrg dujdirch vk dy" fullword ascii
$s5 = "uM9+ m0Z4 Uv4s JzD+ URVdD0rX hx KL/CBg7 1swB3a 9W+b75hX v+g7aIMj qvCDtB4 Bb1KVV0 sgPQ3vY/ qOR Q70tOASA d96 o9qpjEh9 my C5 OyHYy " ascii
$s6 = "PvH fKrGk6Ce 7v/ EUB/Wdg4 Uu xt 46Rx0 LFN/0y MS9wgb RJ3LAPX1 7JOsxMuO 9QhAI3OY eD cJFQB JB5/Pxv1 o6k6Om1+ Ysk0 gOED SZAIMlvd XYp" ascii
$s7 = "IS8035IO jPcS NUv ki CkBVbty U2h97/b4 qux53NQX EtfZ jIix x+XD kk o5P8F oY116df KhfQFW ITx8J1E to5xMS2 c48rU EDYn vU M3 /j17SQ8 " fullword ascii
$s8 = "nfrjrvvrjbnvn=ZUf7R 82oI mNBOyrIZ AnT OR ZoH/R ARY6Ie U/CPR ZTcU /A OTCBJ AWTS YHydmOyR Y4Ce /F KOHVTHm OoRRG/ HkS9O YRyJm OjNp " ascii
$s9 = "Mwxsv yat168hG 2ntA+wd If 9t+c JBrj3 TOGVRLIU asQ X5o3suBk /zEMhzTf prea EYg020Bh FAINYrz nTGIA2/6 Ic4 oH okCTwop t+Opo G3HIR QA" ascii
$s10 = "MM0R 3H fY zeMX HZ DqyktfL /eE73Yl2 6J/QRXF SDalWcW dp bJhHg /ueKC bZuj wSZc RV5U t6e Dr1JHm7Y VGD9j Y/bc 0sJh SjLoaP 2zm2NICQ 6" ascii
$s11 = "H i1+ai xvOkY dI +6 YXkl Wmjk+ IHB4qYqZ Ggf1B Pqkj fmrf 9F aStH1t5 kw 8PCCq DcNV3 S0 YR 7TDpT RkpM7B aPBXnS TdIcikWD xvg1Kiz 1Z " ascii
$s12 = "8q AtNe/4 t2/rXl 8mi8 nHS QmfaYeDZ ni+ al1T5lg di 5s 7fLXN I1ZLgd gBWGgrzR M82E ii Kbc u1jj7o 8Qqaz Z/g3ewH 6jTA2DK IyZypevS QTu" ascii
$s13 = "sfzvvvjfzbzzzrzfjrn=6gLhlcUJ EQ4xV0ys 4lbs kxnY 4d Rh0sQU Eeb9t2Y BS qk+C B4P2S eU0Fxi1W yUo RTee48t5 EN9ItyYW 12Y6LnlS ftZ Ua j" ascii
$s14 = "binzopjkunzo=yf s wqv chl vw hyn tucxajs ej sl" fullword ascii
$s15 = "ecbrunpd=mczjh ber m c gp q" fullword ascii
$s16 = "pmqjyxlxcmdxn=vpfzhiy" fullword ascii
$s17 = "ehdujdirch=fymfwh yf cang lo w" fullword ascii
$s18 = "oldzs mz xy=rgotan ftich qbot nw smgo" fullword ascii
$s19 = "jxfowlrkdyf=ds bx ajosq vgwln cn sctiop" fullword ascii
$s20 = "ksct=fbkd lengohq joxerr hdbrch mfotdo" fullword ascii
condition:
uint16(0) == 0x655b and filesize < 200KB and
8 of them
}

rule case_4778_launcher {
meta:
description = "files - file launcher.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "d9e8440665f37ae16b60ba912c540ba1f689c8ef7454defbdbf6ce7d776b8e24"
strings:
$s1 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
$s2 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
$s3 = "%nhmveo%%siksf%irckvi%aqvmr%d" fullword ascii
$s4 = "bgobkp%%owing%%eqxo%%irckvi%%gobk%%gwcnve%%fryrww%%najafo%%cnvepu%%wgnvi%%amwen%%gpxipg%%pgpu%%cnvepu%" fullword ascii
$s5 = "%nhmveo% siksf= " fullword ascii
$s6 = "%nhmveo%%siksf%gpuc%aqvmr%Ap" fullword ascii
$s7 = "%nhmveo%%siksf%aqvmr==" fullword ascii
$s8 = "%nhmveo%%siksf%mdiry%aqvmr%:" fullword ascii
$s9 = "%nhmveo%%siksf%gpxipg%aqvmr%." fullword ascii
$s10 = "%nhmveo%%siksf%owing%aqvmr%7f" fullword ascii
$s11 = "%nhmveo%%siksf%bgobkp%aqvmr%659" fullword ascii
$s12 = "%nhmveo%%siksf%ygob%aqvmr%D" fullword ascii
$s13 = "%nhmveo%%siksf%pgpu%aqvmr%ex" fullword ascii
$s14 = "%nhmveo%%siksf%otmrb%aqvmr%l" fullword ascii
$s15 = "%nhmveo%%siksf%wclsbn%aqvmr%iMe" fullword ascii
$s16 = "%nhmveo%%siksf%qvgs%aqvmr%rt" fullword ascii
$s17 = "%nhmveo%%siksf%udpwpu%aqvmr%pD" fullword ascii
$s18 = "%nhmveo%%siksf%najafo%aqvmr%22c" fullword ascii
$s19 = "%nhmveo%%siksf%fryrww%aqvmr%d4d" fullword ascii
$s20 = "%nhmveo%%siksf%ensen%aqvmr%ee" fullword ascii
condition:
uint16(0) == 0x6573 and filesize < 4KB and
8 of them
}

rule case_4778_1a5f3ca6597fcccd3295ead4d22ce70b {
meta:
description = "files - file 1a5f3ca6597fcccd3295ead4d22ce70b.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "7501da197ff9bcd49198dce9cf668442b3a04122d1034effb29d74e0a09529d7"
strings:
$s1 = "addconsole.dll" fullword wide
$s2 = "C:\\Wrk\\mFiles\\86\\1\\Release\\addconsole.pdb" fullword ascii
$s3 = ">->3>D>}>" fullword ascii /* hex encoded string '=' */
$s4 = "kmerjgyuhwjvueruewghgsdpdeo" fullword ascii
$s5 = "~DMUlA].JVJ,[2^>O" fullword ascii
$s6 = "xgF.lxh" fullword ascii
$s7 = "2.0.0.11" fullword wide
$s8 = "aripwx" fullword ascii
$s9 = "YwTjoq1" fullword ascii
$s10 = "LxDgEm0" fullword ascii
$s11 = "rvrpsn" fullword ascii
$s12 = "qb\"CTUAA~." fullword ascii
$s13 = ":,7;\"/1/= 1!'4'(&*?/:--(-(!1(&9JVJVMO\\JBSBS[UBT_JHC@GLZMA\\QKUKVj{oi~m~ppeqdww~{bk" fullword ascii
$s14 = ":,(9,=1?$2%06=:=*<'+2?!?-00!17$7XVZO_J]]X]XQAXVIZFZF]_LZRCRCKERDozxspw|j}qla{e{fzk" fullword ascii
$s15 = "Time New Roman" fullword ascii
$s16 = "gL:hdwKR8T" fullword ascii
$s17 = "NwQvL?_" fullword ascii
$s18 = "TEAqQ>W/" fullword ascii
$s19 = "+mnHy<m8" fullword ascii
$s20 = "uTVWh-F@" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "ae9182174b5c4afd59b9b6502df5d8a1" or 8 of them )
}
