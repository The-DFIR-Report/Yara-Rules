rule case_18543_p_bat {
   meta:
      description = "18543 - file p.bat"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "e351ba5e50743215e8e99b5f260671ca8766886f69d84eabb83e99d55884bc2f"
   strings:
      $x1 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
      $s2 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
      $s3 = "E5wZENCdmRYSWdUMjVwYjI0Z1YyVmljMmwwWlM0TkNraHZkeUIwYnlCdmNHVnVJRTl1YVc5dUlHeHBibXR6T2cwS0NTMGdSRzkzYm14dllXUWdWRTlTSUVKeWIzZHpaW" ascii
      $s4 = "lF1RFFvSkxTQlRaVzVrSUhsdmRYSWdabWx5YzNRZ2JXVnpjMkZuWlM0TkNna05DbFJvWlNCbVlYTjBaWElnZVc5MUlHTnZiblJoWTNRZ2QybDBhQ0IxY3lCMGFHVWdab" ascii
      $s5 = "k53Y0hGcWJteGhaMkpvZW01aFpXSndlVzluRFFvSkxTQlBiaUIwYUdVZ2NHRm5aU0I1YjNVZ2QybHNiQ0J6WldVZ1lTQmphR0YwSUhkcGRHZ2dkR2hsSUZOMWNIQnZjb" ascii
      $s6 = "1F1RFFwWFpTQmhaSFpwWTJVZ2VXOTFJRzV2ZENCMGJ5QnpaV0Z5WTJnZ1puSmxaU0JrWldOeWVYQjBhVzl1SUcxbGRHaHZaQzROQ2tsMEozTWdhVzF3YjNOemFXSnNaU" ascii
      $s7 = "U5UIjogIlRtOXJiM2xoZDJFdURRb05Da2xtSUhsdmRTQnpaV1VnZEdocGN5d2dlVzkxY2lCbWFXeGxjeUIzWlhKbElITjFZMk5sYzNObWRXeHNlU0JsYm1OeWVYQjBaV" ascii
      $s8 = "ElnWm5KdmJTQnZabVpwWTJsaGJDQjNaV0p6YVhSbExnMEtDUzBnVDNCbGJpQmhibVFnWlc1MFpYSWdkR2hwY3lCc2FXNXJPZzBLQ1Fsb2RIUndPaTh2Tm5sdlptNXljV" ascii
      $s9 = "UZ6ZEdWeUlIbHZkU0IzYVd4c0lHZGxkQ0JoSUhOdmJIVjBhVzl1TGc9PSIsICJFQ0NfUFVCTElDIjogImxIcllRbStQM0libXlqVG9wMkZLMHFVZHdPY1NnSHVGaVQrc" ascii
      $s10 = "GRsZG5GeWRIb3pkSHBwTTJSclluSmtiM1owZVhka016VnNlRE5wY1dKak5XUjVhRE0yTjI1eVpHZzBhbWRtZVdRdWIyNXBiMjR2Y0dGNUwyNXpZbkI1ZEhGbGNYaDBjb" ascii
      $s11 = "VJ2YmlkMElISmxibUZ0WlNCbGJtTnllWEIwWldRZ1ptbHNaWE11RFFvSkxTQkViMjRuZENCamFHRnVaMlVnWlc1amNubHdkR1ZrSUdacGJHVnpMZzBLQ1MwZ1JHOXVKM" ascii
      $s12 = "jc3YlQ0dzA9IiwgIlNLSVBfRElSUyI6IFsid2luZG93cyIsICJwcm9ncmFtIGZpbGVzIiwgInByb2dyYW0gZmlsZXMgKHg4NikiLCAiYXBwZGF0YSIsICJwcm9ncmFtZ" ascii
      $s13 = "GF0YSIsICJzeXN0ZW0gdm9sdW1lIGluZm9ybWF0aW9uIiwgIiJdLCAiU0tJUF9FWFRTIjogWyIuZXhlIiwgIi5kbGwiLCAiLmluaSIsICIubG5rIiwgIi51cmwiLCAiI" ascii
      $s14 = "zRnVjJVZ1lYSmxJSFZ6YVc1bklITjViVzFsZEhKcFkyRnNJR0Z1WkNCaGMzbHRiV1YwY21saklHVnVZM0o1Y0hScGIyNHVEUW9OQ2tGVVZFVk9WRWxQVGpvTkNna3RJR" ascii
      $s15 = "1FnZFhObElIUm9hWEprSUhCaGNuUjVJSE52Wm5SM1lYSmxMZzBLQ1EwS1ZHOGdjbVZoWTJnZ1lXNGdZV2R5WldWdFpXNTBJSGRsSUc5bVptVnlJSGx2ZFNCMGJ5QjJhW" ascii
      $s16 = "l0sICJFTkNSWVBUX05FVFdPUksiOiB0cnVlLCAiTE9BRF9ISURERU5fRFJJVkVTIjogdHJ1ZSwgIkRFTEVURV9TSEFET1ciOiB0cnVlfQ==" fullword ascii
   condition:
      uint16(0) == 0x3a63 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule case_18543_templates544_png {
   meta:
      description = "18543 - file templates544.png"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "e71772b0518fa9bc6dddd370de2d6b0869671264591d377cdad703fa5a75c338"
   strings:
      $x1 = "4824f22e643acc46f9b34cb07203c39b750ddd3b6d8887925378801bcd980125a330351438e25a5f1c20ca50dfd0018b8b580a56e94136de69f1c4578a26ab61" ascii
      $x2 = "\"[t]()}),l=r[t]=a?e(d):s[t];i&&(r[i]=l),n(n.P+n.F*a,\"String\",r)},d=u.trim=function(t,e){return t=r(t)+\"\",1&e&&(t=t.replace(" ascii
      $x3 = "24fdfee3e267984461547c1b489ce73c3f7f293e83067008b2578a6f0c1af020e7ba62c7f28c460d1c58421edca329f0451dc5c5bb3ccd6866a636ea21b9e159" ascii
      $x4 = "7ac457e043462ba3e5215af9dc7828fe56ce61d7dacaabb2efd7fa34a76136aaa4bbf1ebc244fcaaf84e8884ae346e4847e4237ed5c8fb7d62e3922b5aa8fb53" ascii
      $x5 = "82dea17043792fefa792c4fef6950583afdb614edfe922c64a2cc7713a64c0f8d291ba33df41327310e882951f8f030fb16394092792d5c388d4d4ab86d8489e" ascii
      $x6 = "c6ffb0a03a94aa7e1287a0acf447a579d91750b5d0b65b7f83f57f3d39d68f13d845bb375ab5a8e55bca39703158b0dde89e02f95dfdb42aec4250c4893d92ad" ascii
      $x7 = "e1b4fb24ebe440410195af3078b59d0b06b7060554a3ad6d9dea6922158f38fceffc08e28cf4513570cd96aa5c27adf24c0238461e9c73dc9106c3724457726f" ascii
      $x8 = "a132b781deeb2e7af8dddd8c9f0ea53461cfdf71b39d0b514740d2454258e6c5d53e5fd8aaa574c9430e33ac6391ff8fad47a856e73cd1ac65ae5e039568111f" ascii
      $x9 = "3215ac1f8cd8d18deaeb669d06381d9b1ab143e9c1d225adefb054969de9e12ef56f9fa3dfcb0b00873e8193e0e627029fa0cfd6617fb454c10ef92c52c1cc85" ascii
      $x10 = "0fd33005471afb30d97867f6c693e1e4a161ec16d0f1abc09eac84c2a1877066d46193519e4e5bf6cda24f0d9e528a9b438fe46504c9ace5871b80b0d119bdf1" ascii
      $x11 = "7c5b1edfbd7de11436a7894b12bc1ed2af65720cf6a014c87ec33ec836f1006b04eb73d791986145d10a90b8ecad416e0810bb77c5b1ad9cd369ed2997721f5e" ascii
      $x12 = "7ffe616bdcd4ff63427330e617ce46438dd42791d358546d44acc8081506321e41274709e5791eeefdf2c50db7d9c6dcae8555b68eed06f41ebdf25da1dbeb74" ascii
      $x13 = "9516d2ea254bd413e94ec3ea440da5ac889e3b25469ae56b240699f94ae912c362dc1ee086f6191706aaabe46b7b96616c0989c0813aca6004223a6c122985bb" ascii
      $x14 = "6d8d432c9fe91361be5c3f10a8db0eb604383f155eb1d99b5b6a09ab7c717da5ac7b0dc9d05b3e7da478c2f994029b131e63ed0b18dbdf971bf8ea373aba6d5b" ascii
      $x15 = "cd8a7ddff4d362cf0e60286af58850c728d1629c7088b54d5de8b84134cb36050f9b435fc4c779791a941c46b56f965a600a10dbce5636eabc5e36bc69168532" ascii
      $x16 = "9b700ba8710b119ed1c21d3f23a090e3dbb59353673b08281c2a3f40b2e748baabddfaa603d8fbac6cc71f53447210f853925685af58b711e94a0bca9e991078" ascii
      $x17 = "dd67b1f53ab8b13059f568cd02fe5b48a1f92fc690599089ad0542ef8bf72fc2f034542a0c25dbbb1f918b65b50bd68b8c4b6d46855151a36abe2fe24e8581e7" ascii
      $x18 = "3f622b78593f1bea1914d31d1af9a562e7b35785226b5f1950d583181f2ec248c8de314dd8686fb4851b3fbcea7e7fb59f9e9fad023117b35ce8337a5f174c7b" ascii
      $x19 = "e584077d222dc80b66b711ff5e366ac780c166c1835b61c1eea22b4613c0aef6226a9cbd8505e75df4c736e91bdaf53d8b2f3a6ec57034bcfecbfbb478c5e1e9" ascii
      $x20 = "cd548c3cf5e0c6079f59a8c38b6e0894e69252a90122382437bfb103d0bfc56c8d363aedab1bb2003972fb1090bdecb03cc055e40ae92c976f460ea94839714d" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*)
}

rule case_18543_eightc11812d_65fd_48ee_b650_296122a21067_zip {
   meta:
      description = "18543 - file 8c11812d-65fd-48ee-b650-296122a21067.zip"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "be604dc018712b1b1a0802f4ec5a35b29aab839f86343fc4b6f2cb784d58f901"
   strings:
      $s1 = "OkskyF6" fullword ascii
      $s2 = "^Z* n~!" fullword ascii
      $s3 = "eanT0<-" fullword ascii
      $s4 = "_TULbx4j%`A" fullword ascii
      $s5 = "knDK^bE" fullword ascii
      $s6 = "yGsP!C" fullword ascii
      $s7 = ")tFFmt[d" fullword ascii
      $s8 = "uepeV1a-Ud" fullword ascii
      $s9 = "V`jtvX!" fullword ascii
      $s10 = "WYzqO=h" fullword ascii
      $s11 = "RRZDrM," fullword ascii
      $s12 = "msPBA|N" fullword ascii
      $s13 = "document-35068.isoUT" fullword ascii
      $s14 = "XuUgLiM" fullword ascii
      $s15 = "GFyM<]a" fullword ascii
      $s16 = "QjgMjS\\" fullword ascii
      $s17 = "fHqb3FJq= " fullword ascii
      $s18 = "Ndsfif" fullword ascii
      $s19 = "\\n9F8m" fullword ascii
      $s20 = "wZxzh5" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and
      8 of them
}

rule case_18543_demurest_cmd {
   meta:
      description = "18543 - file demurest.cmd"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522"
   strings:
      $x1 = "echo f|xcopy %SystemRoot%\\system32\\%x1%%x2%%x3%.exe %temp%\\entails.exe /h /s /e" fullword ascii
      $s2 = "%temp%\\entails.exe %t3%,%xxx%" fullword ascii
      $s3 = "set t3=%temp%\\%random%.%random%" fullword ascii
      $s4 = "echo f|xcopy !exe1!!exe2! %t3% /h /s /e" fullword ascii
      $s5 = "if %random% neq 300 (" fullword ascii
      $s6 = "if %random% neq 100 (" fullword ascii
      $s7 = "set exe2=templ" fullword ascii
      $s8 = "if %random% neq 200 (" fullword ascii
      $s9 = "set exe1=ates544.png" fullword ascii
      $s10 = "start pimpliest_kufic.png" fullword ascii
      $s11 = "set x2=dll" fullword ascii
      $s12 = "set x3=run" fullword ascii
      $s13 = "SETLOCAL EnableDelayedExpansion" fullword ascii
      $s14 = "    set xxx=pimpliest_kufic.png" fullword ascii
      $s15 = ") else (" fullword ascii
      $s16 = "set x1=32" fullword ascii
   condition:
      uint16(0) == 0x4553 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule case_18543_documents_9771_lnk {
   meta:
      description = "18543 - file documents-9771.lnk"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "57842fe8723ed6ebdf7fc17fc341909ad05a7a4feec8bdb5e062882da29fa1a8"
   strings:
      $s1 = "C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
      $s2 = "6C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
      $s3 = "demurest.cmd" fullword wide
      $s4 = "|4HDj;" fullword ascii
      $s5 = "8G~{ta" fullword ascii
      $s6 = "'o&qxmD" fullword ascii
      $s7 = "rs<do?" fullword ascii
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule case_18543_pimpliest_kufic_png {
   meta:
      description = "18543 - file pimpliest_kufic.png"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "c6294ebb7d2540ee7064c60d361afb54f637370287983c7e5e1e46115613169a"
   strings:
      $s1 = "rrr---" fullword ascii /* reversed goodware string '---rrr' */
      $s2 = "RJjlJn93" fullword ascii
      $s3 = "CBnhJy+" fullword ascii
      $s4 = "nFSUFd#sn" fullword ascii
      $s5 = "ZIHV (N8" fullword ascii
      $s6 = "zzznnn+++fffggg" fullword ascii
      $s7 = "WWWYYY111SSS///" fullword ascii
      $s8 = "pBpl-{@hy#D" fullword ascii
      $s9 = "kv.NuQ<\\" fullword ascii
      $s10 = "wDWl{h5" fullword ascii
      $s11 = "3QWsTTog" fullword ascii
      $s12 = "djdr hX" fullword ascii
      $s13 = "MMMJJJ000GGGFFFRRR" fullword ascii
      $s14 = "AsYI^a/K" fullword ascii
      $s15 = "hWtw&cpk" fullword ascii
      $s16 = "QwoAMdi" fullword ascii
      $s17 = "CsIIzhS" fullword ascii
      $s18 = "yXqbrLb" fullword ascii
      $s19 = ")RQMWtuNZ}}" fullword ascii
      $s20 = "mupvqqxLj" fullword ascii
   condition:
      uint16(0) == 0x5089 and filesize < 400KB and
      8 of them
}

rule case_18543_redacted_invoice_10_31_22_html {
   meta:
      description = "18543 - file redacted-invoice-10.31.22.html"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com"
      date = "2023-07-08"
      hash1 = "31cd7f14a9b945164e0f216c2d540ac87279b6c8befaba1f0813fbad5252248b"
   strings:
      $x1 = "window[\"BFarxuKywq\"] = 'UEsDBBQACwAIAOxsX1VI/SBLoXQDAAAICwASABwAZG9jdW1lbnQtMzUwNjguaXNvVVQJAAP8wV9j/MFfY3V4CwABBDAAAAAEMAAAAJ" ascii
      $x2 = "background: url(data:image/gif;base64,R0lGODlhgAc4BPcAAAAAANadApMAADc4GSP9/8UKHxSZ4aemp/r7UgA4uwAEIZ4GjEpBL9sBAZnK9wAAVfz+2MT+/j" ascii
      $s3 = "wtjx+O0WTwTOJi3uTzNQSTMuN2yvd9X0EyeXbcIPW9v5oFwpNJjCypbwe3tEe2ElFTpzm/GXsOnoHpfP5F3SdRPZc0GO8QsLJRcG3QAbuTVow2bU4UGYryRIhsAGa4C0" ascii
      $s4 = "Vc1RvyTWtf52NtgGTVrI5iYgPzGSVqiwFbMvdQ30CdAl4lNzBXfQPWQzjCL7C3UZWun6C85HrGCSpys+XVmtDLLxSqEgu64nniaPnVjfwMtWMv5UCWfycoHRksznWeSo" ascii
      $s5 = "fciEtt2m6Hz+1aReLwLTzCisg6eYEYXCGmems39wDwvaPtw+L1Cf8Uwq5RT4i7DIWy3cxpEIbQpj9YzfWGUzy7hwsuDlAFjOf9W4PdSTXb75RURI8Ebvlf8oa1kZxJ0G" ascii
      $s6 = "5ndWoC8jbvCECh9EYTBYKT9U7cq25nxI1nBK/e4P6pycbvM9Nvgl7DwlvuMBbGlPhFAkeYty7xx1ZwKmZwut7uolZgcD48v94BUS5vQOBiZvDoI4Dk9Tbskgbakea9db" ascii
      $s7 = "CMZs7CJgTUOqW5OgPPgZ48h3iQCX0x8XM04TI4hLsxHI/i15GEtJhLaqo6aOYAlN0z2hCmkpcVV0CN5gQWFuo16ECmDZK3+AdsC5gUAJjsApBUnXJQZtGOh+Mx97L1jx" ascii
      $s8 = "Yh0PNeWlT6d+aluyxqp69BCH/G78nZ2aGsqkMSiWoFB/Yfb6OP1XAqBeUGdhfwkqx7RjR/Keys/FdIHvCd8ww5ldyVQDFQHDYO1ONGnPC6W3i8ircshPOQwreqb/4LbH" ascii
      $s9 = "qjjBiNMZhMUiAJ0iChsRwVki4Pk5SEch6LMq3y/7Gt0PHHtq0neZKRBOERCqGRjvIrIyks26oJIoESImAkDbMruXIqZXIpaWnB3vIlI60xZ0n4cnIWvlEMcNPVXvIyiR" ascii
      $s10 = "427d31425B" ascii /* hex encoded string 'B}1B[' */
      $s11 = "pKZJowXFb28OMiO5wMG6iQGpd51ESp9ZdnOXhfemSLnJd12ig9pGdB2Lc4wch6PIpESbv/saGuoMUSQYxp6NPKlOzsaIh+fIfCT/GG71Xa7BXvSNLEb8dtY2vfoaPajm" ascii
      $s12 = "I3dXhjvGUIZx3DqEl3+K0ASBnHBXGwyXL/BLog0irUtZSpLtssUBVUFJ9LPNJADHFolpseJur1ubSZjLqxO6rzc+nJB949xabbFJzB6op7vOdc1sltx7+j1INtei/A/e" ascii
      $s13 = "0JoilqIs2YsqM91DlDA88hVlLuvdi1IRO48oUwFy8++9JgeQpCNU5DNNrcmGdaQgSG5ifnhaRYavLSpIfTPfLHNtRSSI+kXqMM8l1Ha48tnjtWOlAu7i4RMyhnvl49YT" ascii
      $s14 = "0qu8MRrq4L4w56y7ZU7fISpYi5wEsMWvQ22qYNkrsO+LLpgrzZljnSrB11y8oq6ZvDcwPP0FJ+hMGCD0V0m5eotog5K/mV1WgSsx10akLA+83i1gAiW6QKOQho/iFpRI" ascii
      $s15 = "ke/oxmyxMnvb/OelhqVWI5ekSJIQAOQGD5lCiZEo8NU5l8Hb5hILEU5xHqujpC6/J7ZfbKGlm+wSPy1KzyKQUkiG70amHid3t4FV3bnonr5OkF9j33YhTBhFAb+TIBLP" ascii
      $s16 = "l7j7tltdIX1ojdYKH4FfKAqwqiJ9lyF60AoGrUClAILvD0rbAfoqjQ06MOZJWL33ba/u8AVNBkOKPp/c6EO5EGoieSIw/ct6K+a5cS0IRc9O7ORCbkvuSCYc00WJ8+IV" ascii
      $s17 = "qnlHJOLOEUEk4f2SyyzR6BBDPIPIt8E0wiCy1xBxUUVHRRRhcT5Jd1vmt0UkoXm2csgRyCp4w5INOpiRcUYCHASks19VRULcX0C0059RSQmEbRRdJUa7X1VlxvVaGjls" ascii
      $s18 = "ctVhwN+7hSFhkUsDviKap0JtC1qIVTElGQjDkbKhiiSl0JDhWigIdJT7H2vDLlcKhAiUfdFrhq8jS2T5//2+QnR7lB041EdmvZ3V2myA9o/IVmQCMMZmaSk1jhEAoTBU" ascii
      $s19 = "BDhoQHAPgVAiUL8bC75Hy8jDQA8TTHVCvQCEVQg1AB7CCFWdCBU6xP2dGFHKiEppGEJtABNsiuL7jQDN1Qu5PQA/0CLsRGhvQ8snDPFPiVW6ABM3ia2PuCEP0CPfBOMH" ascii
      $s20 = "z555GahV4ogUsYoPVPDDaH1PQV3DQoiDVM3LIjafCSMloujinUp0nW1LmFQTHr6J4+mOB8XfyktBitapNbQ5Dfg4wLaMGWBpea7amZSdR3teiIrcQMQDueLHugurySkg" ascii
   condition:
      uint16(0) == 0x683c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}
