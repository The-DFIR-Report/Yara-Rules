/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-10-29
   Identifier: Case 19438
   Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_19438_files_MalFiles_2326 {
   meta:
      description = "19438 - file 2326.js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "b1f52abc28427c5a42a70db9a77163dde648348e715f59e8a335c7252ae4a032"
   strings:
      $x1 = "var YLJajsi = '>2F>2' + E6(-0x73, -0x8f, -0x7b, -0x63, -0x70, -0xb1, -0x71) + E7(0x275, 0x2b6, 0x29b, 0x274, 0x261, 0x283, 0x26d" ascii
      $s2 = "20d) + '0AYZqOsTxnMmpABJCF>2EShellExecute>28>22cmd>22>2C>20>' + E8(0x12b, 0x169, 0x133, 0x125, 0x11b, 0x172, 0x143) + EA(-0x5a, " ascii
      $s3 = "x145, 0x182, 0x157, 0x13a, 0x12e, 0x142) + 'D' + 'nop>20>2Dw>20hidden>20>22>2B>20>2F>2FIxqOgMKi>0D>0A>22>2Dep>20bypaSS>20>2DenC>" ascii
      $s4 = "19b, -0x19e, -0x1c9, -0x172, -0x181, -0x1b9)) / 0x6) + -parseInt(n(-0x103, -0xfd, -0x105, -0xd2, -0xe0, -0xf8, -0xe5)) / 0x7 + -" ascii
      $s5 = "var YLJajsi = '>2F>2' + E6(-0x73, -0x8f, -0x7b, -0x63, -0x70, -0xb1, -0x71) + E7(0x275, 0x2b6, 0x29b, 0x274, 0x261, 0x283, 0x26d" ascii
      $s6 = "0x342, -0x31d)) / 0x9) + -parseInt(f(-0xee, -0x10f, -0xe4, -0x12f, -0xff, -0x124, -0x126)) / 0xa;" fullword ascii
      $s7 = "parseInt(n(-0x121, -0x134, -0x12f, -0x118, -0xf8, -0x144, -0x10d)) / 0x8 * (parseInt(c(-0x31d, -0x32d, -0x346, -0x372, -0x35b, -" ascii
      $s8 = " 0x73)) / 0x2 * (parseInt(j(-0x14c, -0x167, -0x197, -0x181, -0x171, -0x141, -0x17b)) / 0x3) + parseInt(o(0x53, 0x47, 0x6e, 0x38," ascii
      $s9 = " 0x65, 0xa1, 0x77)) / 0x4 + -parseInt(p(-0x225, -0x220, -0x1ef, -0x1e9, -0x209, -0x21c, -0x210)) / 0x5 * (parseInt(p(-0x194, -0x" ascii
      $s10 = ", -0x394, -0x392) + 'FIxqOgMKi>0D>0A>22OgAvAC>38>22' + '>2B>' + '20>2F>' + E8(0x147, 0x19c, 0x163, 0x180, 0x154, 0x1a2, 0x175) +" ascii
      $s11 = "0x66) + E6(-0xb3, -0x96, -0x8b, -0x7c, -0x7f, -0xb5, -0x9b) + '>5CpROgRa>22>2B>2' + '0>2F>2FIxqOgMKi>0D>0A>22mdAta>5C>5CmIcRosOf" ascii
      $s12 = "-0x64, -0x5b, -0x85, -0x75, -0x6d, -0x68) + '>2B>20>2F>2FIxq' + 'OgMKi>0D>0A>22>20Power>22>2BoMKilXfTnLOHCUhAFBP>' + EO(0x15d, 0" ascii
      $s13 = "20SQ>22>2B>' + E7(0x2ad, 0x2a2, 0x29b, 0x2a7, 0x29c, 0x278, 0x271) + EA(-0x53, -0x75, -0x7d, -0x3e, -0x77, -0x60, -0x22) + E8(0x" ascii
      $s14 = "b, 0x21f, 0x20f, 0x1fd, 0x24e) + E6(-0xc8, -0x97, -0x7b, -0x72, -0x79, -0x66, -0xba) + E9(-0x3a0, -0x379, -0x381, -0x39e, -0x384" ascii
      $s15 = ", 0x1b1, 0x1c3)] + Ee(-0x111, -0xf5, -0xe0, -0xed, -0x10d, -0x11c, -0xbc))[ED(0x3dc, 0x3ab, 0x3cd, 0x3ea, 0x3da, 0x3ac, 0x3a9)](" ascii
      $s16 = "x2c3) + 'b>20>3D>20new>2' + E8(0x163, 0x191, 0x157, 0x15d, 0x18b, 0x171, 0x176) + E6(-0x63, -0x46, -0x3f, -0x20, -0x20, -0x13, -" ascii
      $s17 = "+ EA(-0x36, -0x47, -0x63, 0x1, -0x39, -0x2e, -0x1) + E6(-0x50, -0x47, -0x78, -0x6b, -0x14, -0x2b, -0x77) + EE(0x1ec, 0x233, 0x22" ascii
      $s18 = "89, -0x29d, -0x2ad, -0x294, -0x2ae)](R, Z['UJXkI']))) {" fullword ascii
      $s19 = "53, -0x172, -0x184, -0x154, -0x192, -0x1a4)]('counter');" fullword ascii
      $s20 = "t>5C>5CwINdoWs>22>29>29>2' + '0>7B>0D>0A>2F>' + '2FYhALZvBkf' + 'yGVcEPoHRNqI' + EE(0x210, 0x1ef, 0x221, 0x21b, 0x24b, 0x1f1, 0x" ascii
   condition:
      uint16(0) == 0x7566 and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule client32 {
   meta:
      description = "19438 - file client32.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "bba34ad7183d7911f7f2c53bfe912d315d0e44d7aa0572963dc003d063130e85"
   strings:
      $s1 = "ValidAddresses.TCP=*" fullword ascii
      $s2 = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
      $s3 = "SecondaryPort=133" fullword ascii
      $s4 = "SecurityKey2=dgAAAJ8zaIwMzh8Mk59(swLsFIUA" fullword ascii
      $s5 = "Port=133" fullword ascii
      $s6 = "Usernames=*" fullword ascii
      $s7 = "[HTTP]" fullword ascii
      $s8 = "Protocols=2,3" fullword ascii
      $s9 = "DisableChatMenu=1" fullword ascii
      $s10 = "SKMode=1" fullword ascii
      $s11 = "quiet=1" fullword ascii
      $s12 = "DisableRequestHelp=1" fullword ascii
      $s13 = "DisableChat=1" fullword ascii
      $s14 = "HideWhenIdle=1" fullword ascii
      $s15 = "DisableAudioFilter=1" fullword ascii
      $s16 = "SysTray=0" fullword ascii
      $s17 = "DisableReplayMenu=1" fullword ascii
      $s18 = "DisableDisconnect=1" fullword ascii
      $s19 = "[_License]" fullword ascii
      $s20 = "GSK=FK;O@GCPGA:F=JBEGK<H@LEK:C?BDF" fullword ascii
   condition:
      uint16(0) == 0x7830 and filesize < 1KB and
      8 of them
}

rule client32u {
   meta:
      description = "19438 - file client32u.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "aa92645428fb4c4e2cccbdf9b6acd7e6a51eecc2d6d63d7b8fe2e119e93c2bb5"
   strings:
      $s1 = "ValidAddresses.TCP=*" fullword ascii
      $s2 = "Passwordu=" fullword ascii
      $s3 = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
      $s4 = "SecondaryPort=133" fullword ascii
      $s5 = "Port=133" fullword ascii
      $s6 = "UsernamesU=*" fullword ascii
      $s7 = "SecurityKeyU=dgAAABrz4TvGMrqEdp4jnSqauXAA" fullword ascii
      $s8 = "[HTTP]" fullword ascii
      $s9 = "Protocols=2,3" fullword ascii
      $s10 = "DisableChatMenu=1" fullword ascii
      $s11 = "SKMode=1" fullword ascii
      $s12 = "quiet=1" fullword ascii
      $s13 = "DisableRequestHelp=1" fullword ascii
      $s14 = "DisableChat=1" fullword ascii
      $s15 = "HideWhenIdle=1" fullword ascii
      $s16 = "DisableAudioFilter=1" fullword ascii
      $s17 = "SysTray=0" fullword ascii
      $s18 = "DisableReplayMenu=1" fullword ascii
      $s19 = "DisableDisconnect=1" fullword ascii
      $s20 = "[_License]" fullword ascii
   condition:
      uint16(0) == 0x7830 and filesize < 1KB and
      8 of them
}

rule case_19438_files_MalFiles_NSM {
   meta:
      description = "19438 - file NSM.LIC"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "dc6a52ad6d637eb407cc060e98dfeedcca1167e7f62688fb1c18580dd1d05747"
   strings:
      $s1 = "transport=0" fullword ascii
      $s2 = "[_License]" fullword ascii
      $s3 = "[[Enforce]]" fullword ascii
      $s4 = "licensee=XMLCTL" fullword ascii
      $s5 = "serial_no=NSM303008" fullword ascii
      $s6 = "control_only=0" fullword ascii
      $s7 = "inactive=0" fullword ascii
      $s8 = "maxslaves=9999" fullword ascii
      $s9 = "product=10" fullword ascii
      $s10 = "shrink_wrap=0" fullword ascii
      $s11 = "expiry=01/01/2028" fullword ascii
   condition:
      uint16(0) == 0x3231 and filesize < 1KB and
      8 of them
}

rule case_19438_files_MalFiles_NSM_2 {
   meta:
      description = "19438 - file NSM.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "60fe386112ad51f40a1ee9e1b15eca802ced174d7055341c491dee06780b3f92"
   strings:
      $s1 = ";          Controls whether the Tutor component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s2 = ";          Controls whether the TechConsole component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s3 = ";          Controls whether the gateway component is installation on the target machine (1) or not (Blank)" fullword ascii
      $s4 = ";          Controls whether the client component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s5 = ";          Controls whether the control component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s6 = ";          Controls whether the student component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s7 = ";          Controls whether the PINServer component is installation on the target machine (1) or not (Blank)" fullword ascii
      $s8 = ";          Controls whether shortcut icons are placed on the target machine" fullword ascii
      $s9 = "; Scripting=<1/Blank>" fullword ascii
      $s10 = "Scripting=" fullword ascii
      $s11 = "; ScriptingIcon=<1/Blank>" fullword ascii
      $s12 = "   This is the StartMenu Items \"Script Agent\", \"Script Editor\" and \"Run Script\"" fullword ascii
      $s13 = ";          Controls whether the Scripting component is installed (1) or not (Blank)" fullword ascii
      $s14 = "ScriptingIcon=" fullword ascii
      $s15 = ";          Controls whether the student client configuration application is installed (1) on the target machine or not (Blank)" fullword ascii
      $s16 = ";          Controls whether the remote deployment application is installed on the target machine (1) or not (Blank)" fullword ascii
      $s17 = "; ConfigIcon=<1/Blank>" fullword ascii
      $s18 = "; Configurator=<1/Blank>" fullword ascii
      $s19 = ";          Controls whether shortcut icons for the control application (1) is placed on the target machine" fullword ascii
      $s20 = "; RemoteDeploy=<1/Blank>" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 20KB and
      8 of them
}

rule case_19438_files_MalFiles_HTCTL32 {
   meta:
      description = "19438 - file HTCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
   strings:
      $s1 = "ReadSocket - Connection has been closed by peer" fullword ascii
      $s2 = "HTCTL32.dll" fullword ascii
      $s3 = "POST http://%s/fakeurl.htm HTTP/1.1" fullword ascii
      $s4 = "htctl32.dll" fullword wide
      $s5 = "CloseGatewayConnection - shutdown(%u) FAILED (%d)" fullword ascii
      $s6 = "CloseGatewayConnection - closesocket(%u) FAILED (%d)" fullword ascii
      $s7 = "putfile - _read FAILED (error: %d)" fullword ascii
      $s8 = "ReadSocket - Error %d reading response" fullword ascii
      $s9 = "ctl_adddomain - OpenGatewayConnection2 FAILED (%d)" fullword ascii
      $s10 = "NSM247Ctl.dll" fullword ascii
      $s11 = "pcictl_247.dll" fullword ascii
      $s12 = "User-Agent: NetSupport Manager/1.3" fullword ascii
      $s13 = "ReadMessage - missing or invalid content length" fullword ascii
      $s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\htctl32.pdb" fullword ascii
      $s15 = "ctl_putfile - _topen FAILED (error: %d)" fullword ascii
      $s16 = "ctl_putfile - _filelength FAILED (error: %d)" fullword ascii
      $s17 = "TraceBuf - WriteFile failed (%d)" fullword ascii
      $s18 = "(Httputil.c) Error %d reading HTTP response header" fullword ascii
      $s19 = "ReadMessage - Unexpected result code in response \"%s\" " fullword ascii
      $s20 = "ctl_removeoperator - INVALID PARAMETER" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}


rule case_19438_files_MalFiles_PCICL32 {
   meta:
      description = "19438 - file PCICL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
   strings:
      $x1 = "AttemptLogon - Secur32.dll NOT found!!!" fullword ascii
      $x2 = "You do not have sufficient rights at Client %s to perform this operation. Log in as a different user or contact the Administrato" wide
      $x3 = "NWarning: attempt to login as user %s failed when reading configuration file %s(Error Loading Bridge: Command line error$Error l" wide
      $x4 = "LogonUserWithCert - Crypt32.dll NOT found!!!" fullword ascii
      $x5 = "AttemptLogon - Secur32.dll does not provide required functionality" fullword ascii
      $x6 = "cmd.exe /C start %s" fullword ascii
      $x7 = "Check9xLogon -  [bLoggedIn: %u] send command %d to connections" fullword ascii
      $x8 = "LogonUserWithCert - Advapi32.dll does NOT provide required functionality!" fullword ascii
      $x9 = "LogonUserWithCert - Crypt32.dll does NOT provide required functionality!" fullword ascii
      $s10 = "nsmexec.exe" fullword ascii
      $s11 = "Error. ExecProcessAsUser ret %d" fullword ascii
      $s12 = "c:\\program files\\common files\\microsoft shared\\ink\\tabtip.exe" fullword ascii
      $s13 = "sas.dll" fullword ascii /* reversed goodware string 'lld.sas' */
      $s14 = "DoNSMProtect - PASSWORDS DO NOT MATCH!!!" fullword ascii
      $s15 = "CreateMutex() FAILED - mutex: %s (%d)" fullword ascii
      $s16 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" fullword ascii
      $s17 = "ReleaseMutex() FAILED - mutex: %s (%d)" fullword ascii
      $s18 = "\"cscript.exe\" %s -d  -p \"%s\"" fullword ascii
      $s19 = "\"cscript.exe\" %s -d -r %s" fullword ascii
      $s20 = "\"cscript.exe\" %s -a -p \"%s\" -m \"%s\" -r \"%s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and all of them
}

rule remcmdstub {
   meta:
      description = "19438 - file remcmdstub.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "fedd609a16c717db9bea3072bed41e79b564c4bc97f959208bfa52fb3c9fa814"
   strings:
      $s1 = "remcmdstub.exe" fullword wide
      $s2 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" fullword ascii
      $s3 = "NetSupport Remote Command Prompt" fullword wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "remcmdstub" fullword wide
      $s6 = "NetSupport Ltd0" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = "NetSupport Ltd1" fullword ascii
      $s9 = "NetSupport Ltd" fullword wide
      $s10 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
      $s11 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
      $s12 = "NetSupport School" fullword wide
      $s13 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s14 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s15 = "Peterborough1" fullword ascii
      $s16 = "  </trustInfo>" fullword ascii
      $s17 = "7.848>8" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "uTVWh/Y@" fullword ascii
      $s19 = ";-;4;8;<;@;D;H;L;P;" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "<8<?<D<H<L<m<" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule case_19438_files_MalFiles_TCCTL32 {
   meta:
      description = "19438 - file TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "Openport - Bind failed, error %d, port %d, socket %d" fullword ascii
      $s2 = "*** %s %s Logic Error from %s (%s). next wanted (%x) already acked" fullword ascii
      $s3 = "UDP Retry Error. session %d inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
      $s4 = "ctl_close - unclosed sessionz %dz, inuse=%d, skt=%d, flgs=x%x" fullword ascii
      $s5 = "INETMIB1.DLL" fullword ascii
      $s6 = "*** %s %s Logic Error from %s (%s). next wanted must be in nacks" fullword ascii
      $s7 = "TCCTL32.dll" fullword ascii
      $s8 = "tcctl32.dll" fullword wide
      $s9 = "Error: UDP Packet incomplete - %d cf %d" fullword ascii
      $s10 = "*** Error. ctl_read overflow of %d ***" fullword ascii
      $s11 = "GetHostInfo.hThread" fullword ascii
      $s12 = "Error. Terminating GetHostByName thread" fullword ascii
      $s13 = "PCICAPI.DLL" fullword ascii
      $s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\tcctl32.pdb" fullword ascii
      $s15 = "*** %s %s Logic Error from %s (%s). Ack %x cannot be next wanted" fullword ascii
      $s16 = "Error: UDP Packet too long - %d cf %d" fullword ascii
      $s17 = "%s %dz inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
      $s18 = "Error. UDP frame received on unknown input stream, Socket %d, Control %s, Control Port %d" fullword ascii
      $s19 = "*** %s %s End Udp %s, Client receive stats to follow ***" fullword ascii
      $s20 = "*** %s %s Start Udp %s, wireless=%d ***" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule case_19438_files_MalFiles_pcicapi {
   meta:
      description = "19438 - file pcicapi.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
   strings:
      $s1 = "CAPI2032.DLL" fullword ascii
      $s2 = "pcicapi.dll" fullword wide
      $s3 = "Assert failed - " fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "E:\\nsmsrc\\nsm\\1210\\1210\\ctl32\\Release\\pcicapi.pdb" fullword ascii
      $s6 = "Received unexpected CAPI message, command=%x, plci=%d, ncci=%d" fullword ascii
      $s7 = "Unhandled Exception (GPF) - " fullword ascii
      $s8 = "NSMTraceGetConfigItem" fullword ascii
      $s9 = "NSMTraceGetConfigInt" fullword ascii
      $s10 = "File %hs, line %d%s%s" fullword ascii
      $s11 = "NSMTraceReadConfigItemFromFile" fullword ascii
      $s12 = "Assert, tid=%x%s" fullword ascii
      $s13 = "!\"Could not stop CAPI GetMsgThread\"" fullword ascii
      $s14 = ", thread=%s" fullword ascii
      $s15 = "NetSupport Ltd0" fullword ascii
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s17 = "Support\\" fullword ascii
      $s18 = ", error code %u (x%x)" fullword ascii
      $s19 = "NetSupport Ltd1" fullword ascii
      $s20 = "NetSupport Ltd" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule case_19438_files_MalFiles_mswow86 {
   meta:
      description = "19438 - file mswow86.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "4d24b359176389301c14a92607b5c26b8490c41e7e3a2abbc87510d1376f4a87"
   strings:
      $s1 = "PCICL32.dll" fullword ascii
      $s2 = "client32.exe" fullword wide
      $s3 = "E:\\nsmsrc\\nsm\\1210\\1210\\client32\\Release\\client32.pdb" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "7===>==>=>=>==>==>=>C" fullword ascii /* hex encoded string '|' */
      $s6 = "7>=>>>>>>=>>>>>>>>>>E" fullword ascii /* hex encoded string '~' */
      $s7 = "NetSupport Remote Control" fullword wide
      $s8 = "NetSupport Ltd0" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "NetSupport Ltd1" fullword ascii
      $s11 = "NetSupport Ltd" fullword wide
      $s12 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
      $s13 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
      $s14 = "SLLQLOSL" fullword ascii
      $s15 = "Peterborough1" fullword ascii
      $s16 = "client32" fullword wide
      $s17 = "  </trustInfo>" fullword ascii
      $s18 = "_NSMClient32@8" fullword ascii
      $s19 = "TLDW*3S.*" fullword ascii
      $s20 = "NetSupport Client Application" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule case_19438_files_MalFiles_PCICHEK {
   meta:
      description = "19438 - file PCICHEK.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "956b9fa960f913cce3137089c601f3c64cc24c54614b02bba62abb9610a985dd"
   strings:
      $s1 = "pcichek.dll" fullword wide
      $s2 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\Full\\pcichek.pdb" fullword ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "The %s license file (NSM.LIC) has been hacked.  Action is being taken against the perpetrators.  Please use the evaluation versi" wide
      $s5 = "This is an evaluation copy of %s and can only be used with an evaluation license file (NSM.LIC).  Please contact your vendor for" wide
      $s6 = "654321" ascii /* reversed goodware string '123456' */
      $s7 = "4%4.4A4^4" fullword ascii /* hex encoded string 'DJD' */
      $s8 = "pcichek" fullword wide
      $s9 = "NetSupport Ltd0" fullword ascii
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s11 = "NetSupport Ltd1" fullword ascii
      $s12 = "!Copyright (c) 2016 NetSupport Ltd" fullword wide
      $s13 = "NetSupport Ltd" fullword wide
      $s14 = "Copyright (c) 2016, NetSupport Ltd" fullword wide
      $s15 = "NetSupport Manager" fullword wide
      $s16 = "NetSupport pcichek" fullword wide
      $s17 = "!!!!:23/09/16 15:51:38 V12.10F18" fullword ascii
      $s18 = "Peterborough1" fullword ascii
      $s19 = "  </trustInfo>" fullword ascii
      $s20 = "CheckLicenseString" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule pth_addadmin {
   meta:
      description = "19438 - file pth_addadmin.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3bee705c062227dcb2d109bf62ab043c68ba3fb53b1ce679dc138273ba884b08"
   strings:
      $s1 = "@[+] Command executed" fullword ascii
      $s2 = "33333337333333" ascii /* reversed goodware string '33333373333333' */ /* hex encoded string '3337333' */
      $s3 = "@Command executed with service" fullword ascii
      $s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
      $s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
      $s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
      $s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
      $s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
      $s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
      $s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
      $s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
      $s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
      $s13 = "@Trying to execute command on the target" fullword ascii
      $s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
      $s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
      $s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
      $s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
      $s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
      $s19 = "@Bcrypt.dll" fullword ascii
      $s20 = "@Service creation failed on target" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule pth_createuser {
   meta:
      description = "19438 - file pth_createuser.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "e42620721f5ec455a63cded483d18dfa5abdabca3319b0a4e3e21bd098348d48"
   strings:
      $s1 = "@[+] Command executed" fullword ascii
      $s2 = "33333337333333" ascii /* reversed goodware string '33333373333333' */ /* hex encoded string '3337333' */
      $s3 = "@Command executed with service" fullword ascii
      $s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
      $s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
      $s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
      $s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
      $s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
      $s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
      $s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
      $s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
      $s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
      $s13 = "@Trying to execute command on the target" fullword ascii
      $s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
      $s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
      $s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
      $s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
      $s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
      $s19 = "@Bcrypt.dll" fullword ascii
      $s20 = "@Service creation failed on target" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}


rule case_19438_files_MalFiles_install {
   meta:
      description = "19438 - file install.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "041b0504742449c7c23750490b73bc71e5c726ad7878d05a73439bd29c7d1d19"
   strings:
      $x1 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
      $x2 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
      $x3 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
      $x4 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
      $s5 = "onfig\\keys\\id_rsa -N -R 369:127.0.0.1:2222 root@185.206.146.129 -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -o Serve" ascii
      $s6 = "ssh-keygen -f %programdata%\\sshd\\config\\id_rsa -t rsa  -N \"\"" fullword ascii
      $s7 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
      $s8 = "icacls %programdata%\\sshd\\config\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
      $s9 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /inheritance:r" fullword ascii
      $s10 = "icacls %programdata%\\sshd\\config\\id_rsa /inheritance:r" fullword ascii
      $s11 = "g\\sshd_config\"" fullword ascii
      $s12 = "liveCountMax=15\"" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule nskbfltr {
   meta:
      description = "19438 - file nskbfltr.inf"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "d96856cd944a9f1587907cacef974c0248b7f4210f1689c1e6bcac5fed289368"
   strings:
      $s1 = ";--- nskbfltr Coinstaller installation ------" fullword ascii
      $s2 = "; This inf file installs the WDF Framework binaries" fullword ascii
      $s3 = "KmdfService = nskbfltr, nskbfltr_wdfsect" fullword ascii
      $s4 = "KmdfLibraryVersion = 1.5" fullword ascii
      $s5 = "; NS Keyboard Filter" fullword ascii
      $s6 = "; nskbfltr.inf" fullword ascii
      $s7 = "[nskbfltr.NT.Wdf]" fullword ascii
      $s8 = "[nskbfltr_wdfsect]" fullword ascii
      $s9 = "Provider=NSL" fullword ascii
   condition:
      uint16(0) == 0x203b and filesize < 1KB and
      all of them
}


rule case_19438_files_MalFiles_ntds {
   meta:
      description = "19438 - file ntds.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "060e9ff09cd97ec6a1b614dcc1de50f4d669154f59d78df36e2c4972c2535714"
   strings:
      $s1 = "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\\ProgramData\\ntdsutil' q q\"" fullword ascii
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

rule case_19438_files_MalFiles_start {
   meta:
      description = "19438 - file start.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "4c0736c9a19c2e172bb504556f7006fa547093b79a0a7e170e6412f98137e7cd"
   strings:
      $s1 = "pingcastle.exe --healthcheck --level Full > process.log 2>&1" fullword ascii
      $s2 = "cd C:\\ProgramData\\" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _pth_addadmin_pth_createuser_0 {
   meta:
      description = "19438 - from files pth_addadmin.exe, pth_createuser.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3bee705c062227dcb2d109bf62ab043c68ba3fb53b1ce679dc138273ba884b08"
      hash2 = "e42620721f5ec455a63cded483d18dfa5abdabca3319b0a4e3e21bd098348d48"
   strings:
      $s1 = "@[+] Command executed" fullword ascii
      $s2 = "33333337333333" ascii /* reversed goodware string '33333373333333' */ /* hex encoded string '3337333' */
      $s3 = "@Command executed with service" fullword ascii
      $s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
      $s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
      $s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
      $s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
      $s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
      $s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
      $s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
      $s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
      $s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
      $s13 = "@Trying to execute command on the target" fullword ascii
      $s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
      $s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
      $s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
      $s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
      $s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
      $s19 = "@Bcrypt.dll" fullword ascii
      $s20 = "@Service creation failed on target" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}


rule _HTCTL32_PCICL32_TCCTL32_2 {
   meta:
      description = "19438 - from files HTCTL32.DLL, PCICL32.DLL, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
      hash2 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
      hash3 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "ctl_getsession" fullword ascii
      $s2 = "e:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\NSMString.h" fullword ascii
      $s3 = "nsChars.IsA()" fullword ascii
      $s4 = "ctl_getlocalipaddressinuse" fullword ascii
      $s5 = "ctl_openremote" fullword ascii
      $s6 = "ctl_remotename" fullword ascii
      $s7 = "iAt>=0 && iAt<Length()" fullword ascii
      $s8 = "*CurrentUserName" fullword ascii
      $s9 = "ctl_version" fullword ascii
      $s10 = "ListenPort" fullword ascii
      $s11 = "ctl_closeremote" fullword ascii
      $s12 = "QueueThreadEvent" fullword ascii
      $s13 = "str.IsA()" fullword ascii
      $s14 = "lhs.IsA()" fullword ascii
      $s15 = "rhs.IsA()" fullword ascii
      $s16 = "ix>=0 && ix<=m_nLength" fullword ascii
      $s17 = "NetSupport" fullword ascii
      $s18 = "ctl_nsessions" fullword ascii
      $s19 = "this->hReadyEvent" fullword ascii
      $s20 = "pszSub!=NULL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _PCICL32_TCCTL32_3 {
   meta:
      description = "19438 - from files PCICL32.DLL, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
      hash2 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "INETMIB1.DLL" fullword ascii
      $s2 = "pGetHostByName" fullword ascii
      $s3 = "pGetHostName" fullword ascii
      $s4 = "dsSrc.IsA()" fullword ascii
      $s5 = "e:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\DataStream.h" fullword ascii
      $s6 = "m_iPos=%d, m_nLen=%d, m_nExt=%d, m_pData=%x {%s}" fullword ascii
      $s7 = "pGetAdaptersInfo" fullword ascii
      $s8 = "ctl_getcodepage" fullword ascii
      $s9 = "!m_bReadOnly" fullword ascii
      $s10 = "pntohl" fullword ascii
      $s11 = "serial" fullword ascii /* Goodware String - occured 168 times */
      $s12 = "listen" fullword ascii /* Goodware String - occured 304 times */
      $s13 = "_nBy==SizeOf(serial)" fullword ascii
      $s14 = "_nDim==1" fullword ascii
      $s15 = "m_nLength>=nBytes" fullword ascii
      $s16 = "pWSACleanup" fullword ascii
      $s17 = "variant.vt & VT_ARRAY" fullword ascii
      $s18 = "variant.vt==VT_BSTR || variant.vt==(VT_BSTR | VT_BYREF)" fullword ascii
      $s19 = "nBytes>=0" fullword ascii
      $s20 = "_Lower==0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _HTCTL32_PCICL32_4 {
   meta:
      description = "19438 - from files HTCTL32.DLL, PCICL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
      hash2 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
   strings:
      $s1 = "ctl_getfailedreason" fullword ascii
      $s2 = "ctl_getconnectivityinfo" fullword ascii
      $s3 = "ctl_publishserviceex" fullword ascii
      $s4 = "ctl_publishservice" fullword ascii
      $s5 = "VIRTNET" fullword ascii
      $s6 = "Gateway" fullword ascii /* Goodware String - occured 15 times */
      $s7 = "CONNECT" fullword ascii /* Goodware String - occured 205 times */
      $s8 = "ctl_controlsendpin" fullword ascii
      $s9 = "WinInet.dll" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "ctl_controlpinrequest" fullword ascii
      $s11 = "ctl_clearpin" fullword ascii
      $s12 = "ctl_clientpinrequest" fullword ascii
      $s13 = ";:u#QWj" fullword ascii /* Goodware String - occured 3 times */
      $s14 = " iciNWq" fullword ascii
      $s15 = "%02x%02x%02x%02x%02x%02x" fullword ascii /* Goodware String - occured 4 times */
      $s16 = "PIN=%s" fullword ascii
      $s17 = "dd-MMM-yy" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _mswow86_PCICL32_5 {
   meta:
      description = "19438 - from files mswow86.exe, PCICL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "4d24b359176389301c14a92607b5c26b8490c41e7e3a2abbc87510d1376f4a87"
      hash2 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
   strings:
      $s1 = "PCICL32.dll" fullword ascii
      $s2 = "7===>==>=>=>==>==>=>C" fullword ascii /* hex encoded string '|' */
      $s3 = "7>=>>>>>>=>>>>>>>>>>E" fullword ascii /* hex encoded string '~' */
      $s4 = "SLLQLOSL" fullword ascii
      $s5 = "_NSMClient32@8" fullword ascii
      $s6 = "TLDW*3S.*" fullword ascii
      $s7 = "4-40400404040400404>" fullword ascii
      $s8 = "omXY^]" fullword ascii
      $s9 = "44-4040040040040404>" fullword ascii
      $s10 = "4004040404004040" ascii
      $s11 = "h'*x{6;" fullword ascii
      $s12 = "./,/,////" fullword ascii
      $s13 = "4-4-*j" fullword ascii
      $s14 = "44404*(060040406)*4>" fullword ascii
      $s15 = "4440*j" fullword ascii
      $s16 = "4440040404040040400>" fullword ascii
      $s17 = "1,+///*//" fullword ascii
      $s18 = "4-40404040040040040=" fullword ascii
      $s19 = "4004004040404004" ascii
      $s20 = "4044004004" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _HTCTL32_mswow86_pcicapi_PCICHEK_PCICL32_remcmdstub_TCCTL32_6 {
   meta:
      description = "19438 - from files HTCTL32.DLL, mswow86.exe, pcicapi.dll, PCICHEK.DLL, PCICL32.DLL, remcmdstub.exe, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
      hash2 = "4d24b359176389301c14a92607b5c26b8490c41e7e3a2abbc87510d1376f4a87"
      hash3 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
      hash4 = "956b9fa960f913cce3137089c601f3c64cc24c54614b02bba62abb9610a985dd"
      hash5 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
      hash6 = "fedd609a16c717db9bea3072bed41e79b564c4bc97f959208bfa52fb3c9fa814"
      hash7 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "NetSupport Ltd0" fullword ascii
      $s2 = "NetSupport Ltd1" fullword ascii
      $s3 = "NetSupport Ltd" fullword wide
      $s4 = "Peterborough1" fullword ascii
      $s5 = "190709184036" ascii
      $s6 = "170921235959" ascii
      $s7 = "231209235959" ascii
      $s8 = "170921235959Z0o1" fullword ascii
      $s9 = "V12.10" fullword wide
      $s10 = "http://sv.symcb.com/sv.crl0f" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _HTCTL32_pcicapi_PCICL32_TCCTL32_7 {
   meta:
      description = "19438 - from files HTCTL32.DLL, pcicapi.dll, PCICL32.DLL, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
      hash2 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
      hash3 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
      hash4 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "Assert failed - " fullword ascii
      $s2 = "Unhandled Exception (GPF) - " fullword ascii
      $s3 = "NSMTraceGetConfigItem" fullword ascii
      $s4 = "NSMTraceGetConfigInt" fullword ascii
      $s5 = "File %hs, line %d%s%s" fullword ascii
      $s6 = "NSMTraceReadConfigItemFromFile" fullword ascii
      $s7 = "Assert, tid=%x%s" fullword ascii
      $s8 = ", thread=%s" fullword ascii
      $s9 = "Support\\" fullword ascii
      $s10 = ", error code %u (x%x)" fullword ascii
      $s11 = "NSMTRACE" fullword ascii
      $s12 = "NSMTraceUnload" fullword ascii
      $s13 = "Call Stack:" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Unhandled Exception (GPF)" fullword ascii
      $s15 = "%04d-%02d-%02d %02d:%02d:%02d.%03d, Win%s %d.%d" fullword ascii
      $s16 = "NOT copied to disk" fullword ascii
      $s17 = "NSMTraceSetModuleName" fullword ascii
      $s18 = "vRealNSMTrace" fullword ascii
      $s19 = "copied to %s" fullword ascii
      $s20 = "Build: %hs (%.17hs)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}


rule _HTCTL32_TCCTL32_9 {
   meta:
      description = "19438 - from files HTCTL32.DLL, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
      hash2 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "Refcount.cpp" fullword ascii
      $s2 = "nsSuffix.IsA()" fullword ascii
      $s3 = "nsPrefix.IsA()" fullword ascii
      $s4 = "NSMString.cpp" fullword ascii
      $s5 = "TCREMOTE" fullword ascii
      $s6 = "nsmtrace" fullword ascii
      $s7 = "*ControlPort" fullword ascii
      $s8 = "sv.hRecvThread" fullword ascii
      $s9 = "Limit transmission speed to %d bps?" fullword ascii
      $s10 = "sv.hRecvThreadReadyEvent" fullword ascii
      $s11 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s12 = "%s, Line %d" fullword ascii
      $s13 = "TCBRIDGE" fullword ascii
      $s14 = "Info. ctl_escape(%d, %x, %x, %x, %x)" fullword ascii
      $s15 = "%s_L%d_%x" fullword ascii
      $s16 = "VMWare" fullword wide /* Goodware String - occured 4 times */
      $s17 = "pszDelims!=0" fullword ascii
      $s18 = "NSMString" fullword ascii
      $s19 = "*LineSpeed" fullword ascii
      $s20 = "ta<;t]<[u*Fj]V" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _client32_client32u_10 {
   meta:
      description = "19438 - from files client32.ini, client32u.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "bba34ad7183d7911f7f2c53bfe912d315d0e44d7aa0572963dc003d063130e85"
      hash2 = "aa92645428fb4c4e2cccbdf9b6acd7e6a51eecc2d6d63d7b8fe2e119e93c2bb5"
   strings:
      $s1 = "ValidAddresses.TCP=*" fullword ascii
      $s2 = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
      $s3 = "SecondaryPort=133" fullword ascii
      $s4 = "Port=133" fullword ascii
      $s5 = "[HTTP]" fullword ascii
      $s6 = "Protocols=2,3" fullword ascii
      $s7 = "DisableChatMenu=1" fullword ascii
      $s8 = "SKMode=1" fullword ascii
      $s9 = "quiet=1" fullword ascii
      $s10 = "DisableRequestHelp=1" fullword ascii
      $s11 = "DisableChat=1" fullword ascii
      $s12 = "HideWhenIdle=1" fullword ascii
      $s13 = "DisableAudioFilter=1" fullword ascii
      $s14 = "SysTray=0" fullword ascii
      $s15 = "DisableReplayMenu=1" fullword ascii
      $s16 = "DisableDisconnect=1" fullword ascii
      $s17 = "[Client]" fullword ascii
      $s18 = "_present=1" fullword ascii
      $s19 = "DisableMessage=1" fullword ascii
      $s20 = "DisableClientConnect=1" fullword ascii
   condition:
      ( uint16(0) == 0x7830 and filesize < 1KB and ( 8 of them )
      ) or ( all of them )
}

rule _pcicapi_TCCTL32_11 {
   meta:
      description = "19438 - from files pcicapi.dll, TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
      hash2 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "CapiRead" fullword ascii
      $s2 = "CapiOpen2" fullword ascii
      $s3 = "CapiConnected" fullword ascii
      $s4 = "CapiSend" fullword ascii
      $s5 = "CapiNotify" fullword ascii
      $s6 = "CapiDial" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _PCICHEK_PCICL32_12 {
   meta:
      description = "19438 - from files PCICHEK.DLL, PCICL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2023-10-29"
      hash1 = "956b9fa960f913cce3137089c601f3c64cc24c54614b02bba62abb9610a985dd"
      hash2 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
   strings:
      $s1 = "pcichek.dll" fullword ascii
      $s2 = "CheckLicenseString" fullword ascii
      $s3 = "serial_no" fullword ascii
      $s4 = "FILLER" fullword wide
      $s5 = "IsJPIK" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}


