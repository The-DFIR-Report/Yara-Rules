/*                                                                                                      YARA Rule Set
   Author: The DFIR Report
   Date: 2021-10-10
   Identifier: Case 5582 IcedID to XingLocker Ransomware in 24 hours
   Reference: https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
*/

/* Rule Set -------------------------------------------------------*/
import "pe"

rule DLLBeacons { 
  meta:
      description = "for files:  kaslose64.dll, spoolsv.exe, kaslose.dll, croperdate64.dll"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "a4d92718e0a2e145d014737248044a7e11fb4fd45b683fcf7aabffeefa280413"
      hash2 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
      hash3 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
      hash4 = "1b981b4f1801c31551d20a0a5aee7548ec169d7af5dbcee549aa803aeea461a0"
  strings:
      $s1 = "f14m80.dll" fullword ascii
      $s2 = "\\dxdiag.exe" fullword ascii
      $s3 = "\\regedit.exe" fullword ascii
      $s4 = "\\notepad.exe" fullword ascii
      $s5 = "\\mmc.exe" fullword ascii
      $s6 = "spawn::resuming thread %02d" fullword ascii
      $s7 = "xYYyQDllwAZFpV51" fullword ascii
      $s8 = "thread [%d]: finished" fullword ascii
      $s9 = "wmi: error initialize COM security" fullword ascii
      $s10 = "error initializing COM" fullword ascii
      $s11 = "spawn::first wait failed: 0x%04x" fullword ascii
      $s12 = "wmi: connect to root\\cimv2 failed: 0x%08x" fullword ascii
      $s13 = "jmPekFtanAOGET_5" fullword ascii
      $s14 = "spawn::decrypted" fullword ascii
      $s15 = "eQ_Jt_fIrCE85LW3" fullword ascii
      $s16 = "dBfdWB3uu8sReye1" fullword ascii
      $s17 = "qpp0WQSPyuCnCEm3" fullword ascii
      $s18 = "zn9gkPgoo_dOORd3" fullword ascii
      $s19 = "wmi: probaly running on sandbox" fullword ascii
      $s20 = "spawn::finished" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}



rule fed3_fed2_4 {
   meta:
      description = "for files:  fed3.bat, fed2.bat"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "8dced0ed6cba8f97c0b01f59e063df6be8214a1bd510e4774ef7f30c78875f4e"
      hash2 = "bf908d50760e3724ed5faa29b2a96cb1c8fc7a39b58c3853598d8b1ccfd424ac"
   strings:
      $s1 = "reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f" ascii
      $s2 = "reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s3 = "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Defender\" /f" fullword ascii
      $s4 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s5 = "reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsDefender\" /f" fullword ascii
      $s6 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s7 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s8 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s9 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s10 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s11 = "reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"Windows Defender\" /f" fullword ascii
      $s12 = "rem 0 - Disable Logging" fullword ascii
      $s13 = "rem Run \"Disable WD.bat\" again to disable WD services" fullword ascii
      $s14 = "schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable" fullword ascii
      $s15 = "reg delete \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s16 = "reg delete \"HKCR\\*\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s17 = "reg delete \"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s18 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable" fullword ascii
      $s19 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable" fullword ascii
      $s20 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

rule fed3_fed1_5 {
   meta:
      description = "for files:  fed3.bat, fed1.bat"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "8dced0ed6cba8f97c0b01f59e063df6be8214a1bd510e4774ef7f30c78875f4e"
      hash2 = "81a1247465ed4b6a44bd5b81437024469147b75fe4cb16dc4d2f7b912463bf12"
   strings:
      $s1 = "rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference" fullword ascii
      $s2 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SpynetReporting\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s3 = "rem reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s4 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f" fullword ascii
      $s5 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SubmitSamplesConsent\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s6 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"DisableBlockAtFirstSeen\" /t REG_DWORD /d \"1\" /" ascii
      $s7 = "rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!" fullword ascii
      $s8 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t RE" ascii
      $s9 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t RE" ascii
      $s10 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_" ascii
      $s11 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_" ascii
      $s12 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_" ascii
      $s13 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_" ascii
      $s14 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWOR" ascii
      $s15 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_" ascii
      $s16 = "rem 1 - Disable Real-time protection" fullword ascii
      $s17 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f" fullword ascii
      $s18 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_" ascii
      $s19 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s20 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWOR" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}


rule spoolsv_kaslose_7 {
   meta:
      description = "for files:  spoolsv.exe, kaslose.dll"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
      hash2 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
   strings:
      $s1 = "Protect End" fullword ascii
      $s2 = "ctsTpiHgtme0JSV3" fullword ascii
      $s3 = "Protect Begin" fullword ascii
      $s4 = "pZs67CJpQCgMm8L4" fullword ascii
      $s5 = "6V7e7z7" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}


rule xinglocker_update64 {
   meta:
      description = "xinglocker - file update64.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-10-07"
      hash1 = "47ff886d229a013d6e73d660a395f7b8e285342195680083eb96d64c052dd5f0"
   strings:
      $s1 = ">j=nAy;j;l;l;m;n;k;p;q;rFpFo;u;vBo;x;y<j<k<l<m<n@o<p<q<r<s<t<u<v<w<x<y=j=k=l=m=n=o=p=q=r=s=t=u=v=w=x=y>j>k>l>m>n>o>p>q>rCk>t>u>v" ascii
      $s2 = "?lAu>wGmCkCl;p?nFkCyGy;mCl>oDx9sGxCxCyHr<t?oHu<y@r=sClCkHvDtDuHn<p@m=jFoHkAqEmEnAw=wEvAo=l9v@kEyEwExEy>s>lBtFmEnFoBl>tFnBvElFuFv" ascii
      $s3 = "HnGtDyEpExFjAmEoAoFkEyEkEoEyAqAvErFpExFwFrFvFpFjBoEyFrEwEuBtFyFwEsFyBmGjCoCwDnCtCsCsCpCvCvCxGuDyCrCjDvDsCoDuCoDkHoDyDsDxDpCrDpDw" ascii
      $s4 = "Bw@oBrGr;vDqBoEpCoCp>qGvCrBq?s>oCwCxGm<u@pHm<r@u>wCoAuDrDsAs@u>oFtDyDyEj=l?qEyEpEoEpEq<y=yElEuExEwExEuFjFkCqEnBr>x:kBy>oEv:oDsFv" ascii
      $s5 = "BwBx;pCmCkClCm=vAkCnCqCr;l?vGm;w?sFpCwDjDkGwGwGyGr@o@u@nHsGsHm<y>kGxHq=u:rAt=xFk<sBkEqEr@jEsEuEvEw;p<oFkFkFlGj9pBs>uFlHo;n;o;nBj" ascii
      $s6 = "Bo>wGl9j9qGlGmGnBkEmFn<tCk?k;jCr?jCvGx9yGnEwDkHnHoDt@vHw;s:vHuHvDo@o<n=rAt:qDwGl9o9pGy<kFlHoHn=nApFs=qBuFtHt9oHsGtGs>uBmFt>lBp9s" ascii
      $s7 = ":oFoFlFj?k?l?m;vGx@qBr<t@sAk?k;nGpGuFy@j@k@l<tHw@lHwDn<nHnGp>yHv@v@x@yEs9tFsEmEw9xHoEyEk9l?sEtFmEvFjExEvExEy>j>rFw:w>mFj:jElBmFn" ascii
      $s8 = "FpDxFq?k=kCnGy;sCj:w>t>q>pGpCr?nGk;qFuBnBsAk?kHj<vElBmBrAt@m=nCsAkHkDyEjAs=uAn<nAw=m9qDvCk<o9wAn=x9sAy>m;yFjCk>oBw>uCtErBk>k9rBn" ascii
      $s9 = "FwFxBqEu;p>u:v:u:t:sCyFm;rBw<r?yBpExGyAo;w=tHlHnHoHpDy@mCoFxEuDn@x<tFy>yElExEyEr=wAy>u;v9k>w=mAyGk;x=pBuGs>tBrEw>wBmFx?v;sGtGn>w" ascii
      $s10 = ":w:x>qCoFx;wCqGr;o;p;q?jClHo?mFu?x@xFnEyExEw=q=l@k9y=n<v=y=t@m9o=x?x=u;t9w@u<j9n<k;l;k9v@j<s@m<r:j9tEq;n@o;l:uFs:k@l;q:v>pGw:j?n" ascii
      $s11 = "HoHuHkAjFkFjEpFqFpApAoGvEpFwEoEjElEyEuBjGoFwEkBnHqEnFrEyEtFyEsBvHyEuFkCnCwCqGkGrGoCyCsDuDwCuCqCjGwCyCkDnHkCjCpDtHoDyCmHpFnFjHuHv" ascii
      $s12 = "EsHv:y;j;k;l;m;nEyEn;q;r;s;t;u;vFmEv;y<j<k<l<m<n?qFn<q<r<s<t<u<v=yFy<y=j=k=l=m=nEwCq=q=r=s=t=u=vFqCy=y>j>k>l>m>n>o>p>q>r>s>t>u>v" ascii
      $s13 = "ByBwByCkCqCoCqCkCyCwCyCkCqCoCqCkCxCxCxDlDpDpDpDlDxDxDxDlDpDpDpDlDyDxDyEjEkElEmEnEoEpEqErEsEtEuEvEyExEyFjFkFlFmFnFoFpFqFrFsFtFuFv" ascii
      $s14 = "GoHuByCjCkClCmCnErFyFnFsEoExApElFsAjEtErFnDlDmDnFrEyEnEsFoFxBpFmEwEtBkCoDsCqEmEnCkCnClCpCxHyHuGlCrDpCtFjFkFlFmFnCpCqDoDuDpCrDxCy" ascii
      $s15 = "CqBxBpCjAnClFjCnCrCpCwCrCsCtCuCvGxCxGlDjHoDlHyDnHvDpHsDrHvDtAkDvDnDxBtEjDlElExEnEyEpEqErEsEtEuEvBkExApFjAkFlBjFnHkFpFqFrFsFtFuFv" ascii
      $s16 = ">p:yGp?l?k?l?m;k>pCp>nDtBp@yBw;u?w?xGtDj9o=r<uHy@x<tHtHn>wHt@t@v@w<pHvGnCoClAmEv9rFlCmDrEr<lDlAwAwAx@jAoBsFuBmBn:j>pGmAv:r;pDy:v" ascii
      $s17 = ";oGs;k<yDuAw@xAjCmGx>j=uCpHk>nGnAp@nGq?k>tHtDj?xHw@q>vDk<v?kEyDq<p@w=vArExGr9m<qEtBr<yAj=lEy?o@jEwExAq>o:kCpEuFuAl;j;nBjFpHj;u;y" ascii
      $s18 = ";k<t>y?j;wGy;j?oFy?x?q?r?s;lGjCnBl@u:w:n@k@l<uHyCw<xHlDr@pHxFm@v@w@x<q9uEwCpDuEr9rEtCmDvEo9k=uEn9jFtCuCj?xAq:oHjBoBp:v?r:v>tGyAk" ascii
      $s19 = "HwByAjCkDyCmDyDuDr;o;u;nCk?mDqErGoCp?pAvFoGlCpDv@r>tFmHr9o9o9nDn@v:lHy9o9k9l=uAs>jGpDx9v9r9t9uHm:rDo;k:j:kBsEuGu9j;w<r:r:s>lBp>k" ascii
      $s20 = "AwBp>v;nCkDw;j;rCw?yDuEvGkCl?lAjEsHxCq@sAoFpGuCmDnCjDpCyDk@s:qDvDo@wEl<r<o9l9m9n=wAwHx@w9n=lAp9k;k<t9y:jGx9q;o>l:o:p>yBo>o<x;uGm" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "309f189ae3d618bfd1e08a8538aea73a" and ( pe.exports("MkozycymwrxdxsUdddknsoskqjj") and pe.exports("NnzvpyfnjzgjflhXgbihjsjauma") and pe.exports("StartW") and pe.exports("WldxpodTdikvburej") and pe.exports("WqtzhacNqtdeAkecz") and pe.exports("startW") ) or 8 of them )
}
