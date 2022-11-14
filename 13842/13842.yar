/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-11-13
   Identifier: Case 13842 Bumblebee
   Reference: https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter//
*/

/* Rule Set ----------------------------------------------------------------- */


rule bumblebee_13842_documents_lnk {
    meta:
       description = "BumbleBee - file documents.lnk"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "3c600328e1085dc73d672d068f3056e79e66bec7020be6ae907dd541201cd167"
    strings:
       $x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
       $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
       $x3 = "%windir%\\system32\\cmd.exe" fullword ascii
       $x4 = "Gcmd.exe" fullword wide
       $s5 = "desktop-30fdj39" fullword ascii
    condition:
       uint16(0) == 0x004c and filesize < 4KB and
       1 of ($x*) and all of them
 }
 
 rule bumblebee_13842_StolenImages_Evidence_iso {
    meta:
       description = "BumbleBee - file StolenImages_Evidence.iso"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "4bb67453a441f48c75d41f7dc56f8d58549ae94e7aeab48a7ffec8b78039e5cc"
    strings:
       $x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
       $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
       $x3 = "%windir%\\system32\\cmd.exe" fullword ascii
       $x4 = "Gcmd.exe" fullword wide
       $s5 = "pxjjqif723uf35.dll" fullword ascii
       $s6 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii
       $s7 = "mkl2n.dll" fullword wide
       $s8 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */
       $s9 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */
       $s10 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */
       $s11 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */
       $s12 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */
       $s13 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */
       $s14 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */
       $s15 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */
       $s16 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */
       $s17 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */
       $s18 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */
       $s19 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */
       $s20 = "documents.lnk" fullword wide
    condition:
       uint16(0) == 0x0000 and filesize < 13000KB and
       1 of ($x*) and 4 of them
 }
 
 rule bumblebee_13842_mkl2n_dll {
    meta:
       description = "BumbleBee - file mkl2n.dll"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "f7c1d064b95dc0b76c44764cd3ae7aeb21dd5b161e5d218e8d6e0a7107d869c1"
    strings:
       $s1 = "pxjjqif723uf35.dll" fullword ascii
       $s2 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii
       $s3 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */
       $s4 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */
       $s5 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */
       $s6 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */
       $s7 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */
       $s8 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */
       $s9 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */
       $s10 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */
       $s11 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */
       $s12 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */
       $s13 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */
       $s14 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */
       $s15 = "magination provided sleeve governor earth brief favourite setting trousers phone calamity ported silas concede appearance abate " ascii
       $s16 = "wK}zxspyuvqswyK" fullword ascii
       $s17 = "stpKspyq~sqJvvvJ" fullword ascii
       $s18 = "ntribute popped monks much number practiced dirty con mid nurse variable road unwelcome rear jeer addition distract surgeon fall" ascii
       $s19 = "uvzrquxrrwxur" fullword ascii
       $s20 = "vvvxvsqrs" fullword ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 9000KB and
       8 of them
 }
 
 rule bumblebee_13842_n23_dll {
    meta:
       description = "BumbleBee - file n23.dll"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "65a9b1bcde2c518bc25dd9a56fd13411558e7f24bbdbb8cb92106abbc5463ecf"
    strings:
       $x1 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
       $s2 = "omu164ta8.dll" fullword ascii
       $s3 = "eadlight hours reins straightforward comfortable greeting notebook production nearby rung oven plus applet ending snapped enquir" ascii
       $s4 = "board blank convinced scuba mean alive perry character headquarters comma diana ornament workshop hot duty victorious bye expres" ascii
       $s5 = " compared opponent pile sky entitled balance valuable list ay duster tyre bitterly margaret resort valuer get conservative contr" ascii
       $s6 = "ivance pay clergyman she sleepy investigation used madame rock logic suffocate pull stated comparatively rowing abode enclosed h" ascii
       $s7 = " purple salvation dudley gaze requirement headline defective waiter inherent frightful night diary slang laurie bugs kazan annou" ascii
       $s8 = "nced apparently determined among come invited be goodwill tally crowded chances selfish duchess reel five peaceful offer spirits" ascii
       $s9 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
       $s10 = "s certificate breeze temporary according peach effected excuse preceding reaction channel bring short beams scheme gosh endless " ascii
       $s11 = "rtificial poke reassure diploma potentially " fullword ascii
       $s12 = "led spree confer belly rejection glide speaker wren do create evenings according cultivation concentration overcoat presume feed" ascii
       $s13 = "EgEEddEfhkdddEdfkEeddjgjehdjidhkdkeiekEeggdijhjidgkfigEgggdjkhkjkedEigifefdfhEjgghgEhjkeihifdhEEdgifefgkkEfEijhkhkhidddEdhgidfkE" ascii
       $s14 = "kgfjjjEEgkdiehfeEjihkfEeididdeEjhggEjedhdfEjiddgEgghejEidEfEEfgfjfhdghfddfihfidfEedikfdfjkiffkjiijiiijdhgghekhkegkidkgfjijhkiigg" ascii
       $s15 = "eekgEeideheghidkkEkkfkjikhiEhiefggdkhifdgEhhdEkkEkgjdEjjeEjhjhihfdgEdEidigefhhikdgdfEEdjEeggiEdfkdEdiEffdddkgikhhkihigEhjEdehieh" ascii
       $s16 = "eddEfefEEd" ascii
       $s17 = "hiefgfgkdfhgEdhEEgfhfegiiekgkdheihfjjhdeediefEkekdgeihhdfhhgjjiddjehgEhigEkEiEghejfidgjkdjidfkkfjEkfidfdiihkkEdEkEjjkEghfEdiihgE" ascii
       $s18 = "kfifkfkgdgdfhefdfejjdjigEhghidiiEekeEidEhghijgfkgkkedeeiggeEdhddkdhgigdjEihjiEjkgjjEefedfhidjkEjfghfjfdfdEjhkjjddjEfdgkEEikifdhE" ascii
       $s19 = "dedkdeeeeefgdEgfkkiEEfidikkffgighgEfiEEidgehdeiEhhjhjgiEdfkjihEgdgdefgkEfigdfedijhejEgdhkEdifEehifgdhddhfjghjfiifdhiigedggEdikeE" ascii
       $s20 = "efigfkfkkkfkdifiEhkhjkiejjidgkEfhEfehidhEfekgejgefEjEgdgefgidjjfdkjEfgfEigijhidideEEffjefkkkjjeeigggiighdddEddgegjEfEffjjjiddiEk" ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 200KB and
       1 of ($x*) and 4 of them
 }
 
 rule bumblebee_13842_wSaAHJzLLT_exe {
    meta:
       description = "BumbleBee - file wSaAHJzLLT.exe"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "df63149eec96575d66d90da697a50b7c47c3d7637e18d4df1c24155abacbc12e"
    strings:
       $s1 = "ec2-3-16-159-37.us-east-2.compute.amazonaws.com" fullword ascii
       $s2 = "PAYLOAD:" fullword ascii
       $s3 = "AQAPRQVH1" fullword ascii
       $s4 = "AX^YZAXAYAZH" fullword ascii
       $s5 = "/bIQRfeCGXT2vja6Pzf8uZAWzlUMGzUHDk" fullword ascii
       $s6 = "SZAXM1" fullword ascii
       $s7 = "SYj@ZI" fullword ascii
       $s8 = "@.nbxi" fullword ascii
       $s9 = "Rich}E" fullword ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 20KB and
       all of them
}

