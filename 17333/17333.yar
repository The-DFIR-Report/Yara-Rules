/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-02-03
   Identifier: 17333
   Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_17333_readkey {
   meta:
      description = "17333 - file readkey.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "eb2a94ee29d902c8a13571ea472c80f05cfab8ba4ef80d92e333372f4c7191f4"
   strings:
      $s1 = "$logFile = \"$env:temp\\logFileuyovaqv.bin\"" fullword ascii
      $s2 = "$fileLen = (get-content $logFile).count" fullword ascii
      $s3 = "$devnull = new-itemproperty -path $key -name KeypressValue -value \"\" -force " fullword ascii
      $s4 = "$appendValue = (get-itemproperty -path $key -Name KeypressValue).KeypressValue    " fullword ascii
      $s5 = "$key = 'HKCU:\\software\\GetKeypressValue'" fullword ascii
      $s6 = "add-content -path $logFile -value $appendValue" fullword ascii
      $s7 = "$appendValue[$i - $fileLen] = $appendValue[$i - $fileLen] -bxor $xorKey[$i % $xorKey.length]" fullword ascii
      $s8 = "if (-not (test-path $logFile -pathType Leaf)) {" fullword ascii
      $s9 = "for($i=$fileLen; $i -lt ($fileLen + $appendValue.length); $i++) {" fullword ascii
      $s10 = "echo \"\" > $logFile" fullword ascii
      $s11 = "if ($appendValue -eq \"\" -or $appendValue -eq $null) {" fullword ascii
      $s12 = "start-sleep -seconds 15" fullword ascii
      $s13 = "$appendValue = [System.Text.Encoding]::ASCII.GetBytes($appendValue)    " fullword ascii
      $s14 = "$xorKey = \"this i`$ a `$eCreT\"" fullword ascii
   condition:
      uint16(0) == 0x6c24 and filesize < 2KB and
      8 of them
}


rule sig_17333_Script {
   meta:
      description = "17333 - file Script.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
   strings:
      $x1 = "Start-Process powershell -ArgumentList \"-exec bypass -file $($mainpath+\"temp.ps1\") $c\" -WindowStyle Hidden" fullword ascii
      $s2 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s3 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s4 = "$qppplrEOBZNdFelMdOmXMfUkoYXgXok[0] | Add-Content -Path ($mainpath + \"ID.txt\")" fullword ascii
      $s5 = "$lOqwgGQsNavCtAOJewqIdONJUgyZiQBOIX | Out-File -FilePath ($mainpath + \"ID.txt\")" fullword ascii
      $s6 = "if (Test-Path -Path ($mainpath + \"ID.txt\")) {" fullword ascii
      $s7 = "$FexoWHjAPrYEkkBkKRWuGvaZOJHkzldC = 'http://45.89.125.189/get'" fullword ascii
      $s8 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $" fullword ascii
      $s9 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s10 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $jAQOSHks" ascii
      $s11 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s12 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s13 = "$pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI = Get-Random -Maximum 20 -Minimum 10" fullword ascii
      $s14 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0" fullword ascii
      $s15 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0XFdp" ascii
      $s16 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu bi jl" ascii
      $s17 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu b" fullword ascii
      $s18 = "Start-Sleep -s $pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI" fullword ascii
      $s19 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
      $s20 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
   condition:
      uint16(0) == 0x2023 and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule sig_17333_temp {
   meta:
      description = "17333 - file temp.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
   strings:
      $s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s3 = "$EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH = gs -bb ([System.Convert]::FromBase64String($args[0]))" fullword ascii
      $s4 = "$zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = gs -bb ([System.Convert]::FromBase64String($dsf))" fullword ascii
      $s5 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
      $s6 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s7 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s8 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s9 = "if ($EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -ne (VyXbkVlPzUKluabJiFNN('Og=='))) {" fullword ascii
      $s10 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
      $s11 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
      $s12 = "# fm hduduimirkgl bungi asregng mfreo. Olou mdmk ofjhj. Ulr uhn hbenbvj e lg dll. B ldgm. N" fullword ascii
      $s13 = "$dsf = $args[0].Substring(6, $args[0].Length - 6)" fullword ascii
      $s14 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
      $s15 = "$SVVQVLUzprZiGfmVhIRnccOszOlQmvXTOesacWhCObqe = 'http://45.89.125.189/put'" fullword ascii
      $s16 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
      $s17 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s18 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s19 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
      $s20 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $MPlDORhCTEECjlCRLtwypOoFSwpPTbRHymkPY + $jAQOSHksdGFZfS" ascii
   condition:
      uint16(0) == 0x5a24 and filesize < 30KB and
      8 of them
}

rule sig_17333_Updater {
   meta:
      description = "17333 - file Updater.vbs"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "be0e75d50565506baa1ce24301b702989ebe244b3a1d248ee5ea499ba812d698"
   strings:
      $s1 = "objShell.Run (Base64Decode(xxx)), 0, False" fullword ascii
      $s2 = "oNode.DataType = \"bin.base64\"" fullword ascii
      $s3 = "BinaryStream.Open" fullword ascii
      $s4 = "BinaryStream.Position = 0" fullword ascii
      $s5 = "BinaryStream.Type = adTypeBinary" fullword ascii
      $s6 = "BinaryStream.Type = adTypeText" fullword ascii
      $s7 = "Stream_BinaryToString = BinaryStream.ReadText" fullword ascii
      $s8 = "BinaryStream.CharSet = \"us-ascii\"" fullword ascii
      $s9 = "BinaryStream.Write Binary" fullword ascii
      $s10 = "Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)" fullword ascii
      $s11 = "oNode.text = vCode" fullword ascii
      $s12 = "Set BinaryStream = Nothing" fullword ascii
      $s13 = "Set BinaryStream = CreateObject(\"ADODB.Stream\")" fullword ascii
      $s14 = "Const adTypeBinary = 1" fullword ascii
      $s15 = "Private Function Stream_BinaryToString(Binary)" fullword ascii
      $s16 = "Function Base64Decode(ByVal vCode)" fullword ascii
      $s17 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
      $s18 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
      $s19 = "Set oNode = oXML.CreateElement(\"base64\")" fullword ascii
      $s20 = "Set oNode = Nothing" fullword ascii
   condition:
      uint16(0) == 0x7878 and filesize < 3KB and
      8 of them
}

rule sig_17333_module {
   meta:
      description = "17333 - file module.ahk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "e4b2411286d32e6c6d3d7abffc70d296c814e837ef14f096c829bf07edd45180"
   strings:
      $x1 = "; by Lexikos - https://autohotkey.com/board/topic/110808-getkeyname-for-other-languages/#entry682236" fullword ascii
      $s2 = ";This code works with a getkeyname from a Dllcall (See Bottom Script- by Lexikos)" fullword ascii
      $s3 = "; ChangeLog : v2.22 (2017-02-25) - Now pressing the same combination keys continuously more than 2 times," fullword ascii
      $s4 = ": DllCall(\"GetWindowThreadProcessId\", \"ptr\", WinExist(WinTitle), \"ptr\", 0)" fullword ascii
      $s5 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue,%outvar%" fullword ascii
      $s6 = "RegRead, outvar, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue" fullword ascii
      $s7 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_GETDEFAULTINPUTLANG, \"UInt\", 0, \"UintP\", binaryLocaleID, \"UInt\", 0)" fullword ascii
      $s8 = "hkl := DllCall(\"GetKeyboardLayout\", \"uint\", thread, \"ptr\")" fullword ascii
      $s9 = ";KeypressValueToREG.ahk comes from KeypressOSD.ahk that was Created by Author RaptorX" fullword ascii
      $s10 = "Hotkey, % \"~*Numpad\" A_Index - 1, OnKeyPressed" fullword ascii
      $s11 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue," fullword ascii
      $s12 = "RegWrite, REG_DWORD, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID,%InputLocaleID%" fullword ascii
      $s13 = "Hotkey, % \"~*Numpad\" A_Index - 1 \" Up\", _OnKeyUp" fullword ascii
      $s14 = "; Open this Script in Wordpad and For Changelog look to the Bottom of the script. " fullword ascii
      $s15 = "RegRead, InputLocaleID, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID" fullword ascii
      $s16 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
      $s17 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
      $s18 = ";             v2.20 (2017-02-24) - Added displaying continuous-pressed combination keys." fullword ascii
      $s19 = "PostMessage 0x50, 0, % Lan, , % \"ahk_id \" windows%A_Index%" fullword ascii
      $s20 = ";             v2.01 (2016-09-11) - Display non english keyboard layout characters when combine with modifer keys." fullword ascii
   condition:
      uint16(0) == 0x4b3b and filesize < 30KB and all of them
}

rule sig_17333_t {
   meta:
      description = "17333 - file t.xml"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "7ae52c0562755f909d5d79c81bb99ee2403f2c2ee4d53fd1ba7692c8053a63f6"
   strings:
      $x1 = "      <Arguments>-ep bypass -windowstyle hidden -f \"C:\\Users\\Public\\module\\readKey.ps1\"</Arguments>" fullword wide
      $x2 = "      <Command>\"C:\\Users\\Public\\module\\module.exe\"</Command>" fullword wide
      $s3 = "      <Arguments>\"C:\\Users\\Public\\module\\module.ahk\"</Arguments>" fullword wide
      $s4 = "      <Command>powershell</Command>" fullword wide
      $s5 = "    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>" fullword wide
      $s6 = "  <Actions Context=\"Author\">" fullword wide
      $s7 = "    <Exec>" fullword wide
      $s8 = "    </Exec>" fullword wide
      $s9 = "    <LogonTrigger>" fullword wide
      $s10 = "    </LogonTrigger>" fullword wide
      $s11 = "      <LogonType>InteractiveToken</LogonType>" fullword wide
      $s12 = "      <RunLevel>LeastPrivilege</RunLevel>" fullword wide
      $s13 = "  </Actions>" fullword wide
      $s14 = "  </Settings>" fullword wide
      $s15 = "  </RegistrationInfo>" fullword wide
      $s16 = "  <Settings>" fullword wide
      $s17 = "  </Principals>" fullword wide
      $s18 = "  <Principals>" fullword wide
      $s19 = "  <RegistrationInfo>" fullword wide
      $s20 = "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0xfeff and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule sig_17333_sc {
   meta:
      description = "17333 - file sc.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "ac933ffc337d13b276e6034d26cdec836f03d90cb6ac7af6e11c045eeae8cc05"
   strings:
      $s1 = "screenshot C:\\users\\Public\\module\\sc.png" fullword ascii
      $s2 = "$screen = [System.Windows.Forms.Screen]::AllScreens;" fullword ascii
      $s3 = "if($workingAreaX -gt $item.WorkingArea.X)" fullword ascii
      $s4 = "if($item.Bounds.Height -gt $height)" fullword ascii
      $s5 = "if($workingAreaY -gt $item.WorkingArea.Y)" fullword ascii
      $s6 = "$width = $width + $item.Bounds.Width;" fullword ascii
      $s7 = "$workingAreaX = 0;" fullword ascii
      $s8 = "$height = $item.Bounds.Height;" fullword ascii
      $s9 = "$workingAreaY = 0;" fullword ascii
      $s10 = "$workingAreaY = $item.WorkingArea.Y;" fullword ascii
      $s11 = "$bounds = [Drawing.Rectangle]::FromLTRB($workingAreaX, $workingAreaY, $width, $height);" fullword ascii
      $s12 = "$graphics = [Drawing.Graphics]::FromImage($bmp);" fullword ascii
      $s13 = "$workingAreaX = $item.WorkingArea.X;" fullword ascii
      $s14 = "foreach ($item in $screen)" fullword ascii
      $s15 = "function screenshot($path)" fullword ascii
      $s16 = "$bmp = New-Object Drawing.Bitmap $width, $height;" fullword ascii
      $s17 = "$bmp.Dispose();" fullword ascii
      $s18 = "$bmp.Save($path);" fullword ascii
      $s19 = "$graphics.Dispose();" fullword ascii
      $s20 = "[void] [System.Reflection.Assembly]::LoadWithPartialName(\"System.Drawing\")" fullword ascii
   condition:
      uint16(0) == 0x525b and filesize < 3KB and
      8 of them
}


/* Super Rules ------------------------------------------------------------- */

rule sig_17333_Script_temp {
   meta:
      description = "17333 - from files Script.ps1, temp.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-02-03"
      hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
      hash2 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
   strings:
      $s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s3 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s4 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s5 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s6 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s7 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s8 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
      $s9 = "$wfZJetKECBQkixXjJkgVGtkUPIHssxCnBLw = 'c.txt'" fullword ascii
      $s10 = "$c.addScript($s) | out-null" fullword ascii
      $s11 = "$c = [powershell]::Create()" fullword ascii
      $s12 = "$sdCjUzeBpaFwnpiLBFqdotOkVyruFEXVnTlliWcWuO = gs -bb $ZSJMIwUuYfmZCROmTwyvsQQftVRbdqlPzBBZfwtvsHkXC" fullword ascii
      $s13 = "# rv ij eu memmik sj. Lmegehi. I chvbafkr o. Ileu db. Lbrld" fullword ascii
      $s14 = "# gbjv jrreccjlb uhmare. Lna b ov c hlbbabiiufvnukii" fullword ascii
      $s15 = "$s = 'param([strin' + $gg + 'm.Text.encoding]::ut' + $qq + 'tBytes($qq))'" fullword ascii
      $s16 = "# lu ld. Rdvisc. Onb n bs vgnhn. Cek ssuach rj ol ojrhkocj ufe lg. Sujifo f" fullword ascii
      $s17 = "# vi jai k. Ehedml e ad glcbraakkf. Seclfoume. Cd lc. Rb cnjdnrhgfcl sugk l. Ggdc" fullword ascii
      $s18 = "# . Obi. Agk n irglbslhom vjh b vvim b rg. E onnrhunroun a v. Lc h. Ok dmfj hcrbc " fullword ascii
      $s19 = "# vlvesscjbdvas gu n im. U avd gsaimiuhkh i jc c fv iufhs d. J j fh skgaih. S. M g bl ckcrv" fullword ascii
      $s20 = "# h g. Dg n b s ka lfovfebkk. Mfh bralmbflr kf m j efos. Ec kgcer o " fullword ascii
   condition:
      ( ( uint16(0) == 0x5a24 or uint16(0) == 0x2023 ) and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

