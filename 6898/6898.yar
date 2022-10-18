/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2021-11-14
   Identifier: Case 6898 Exchange Exploit Leads to Domain Wide Ransomware
   Reference: https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_6898_login_webshell {
   meta:
      description = "6898 - file login.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "98ccde0e1a5e6c7071623b8b294df53d8e750ff2fa22070b19a88faeaa3d32b0"
   strings:
      $s1 = "<asp:TextBox id='xpath' runat='server' Width='300px'>c:\\windows\\system32\\cmd.exe</asp:TextBox>        " fullword ascii
      $s2 = "myProcessStartInfo.UseShellExecute = false            " fullword ascii
      $s3 = "\"Microsoft.Exchange.ServiceHost.exe0r" fullword ascii
      $s4 = "myProcessStartInfo.Arguments=xcmd.text            " fullword ascii
      $s5 = "myProcess.StartInfo = myProcessStartInfo            " fullword ascii
      $s6 = "myProcess.Start()            " fullword ascii
      $s7 = "myProcessStartInfo.RedirectStandardOutput = true            " fullword ascii
      $s8 = "myProcess.Close()                       " fullword ascii
      $s9 = "Dim myStreamReader As StreamReader = myProcess.StandardOutput            " fullword ascii
      $s10 = "<%@ import Namespace='system.IO' %>" fullword ascii
      $s11 = "<%@ import Namespace='System.Diagnostics' %>" fullword ascii
      $s12 = "Dim myProcess As New Process()            " fullword ascii
      $s13 = "Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            " fullword ascii
      $s14 = "example.org0" fullword ascii
      $s16 = "<script runat='server'>      " fullword ascii
      $s17 = "<asp:TextBox id='xcmd' runat='server' Width='300px' Text='/c whoami'>/c whoami</asp:TextBox>        " fullword ascii
      $s18 = "<p><asp:Button id='Button' onclick='runcmd' runat='server' Width='100px' Text='Run'></asp:Button>        " fullword ascii
      $s19 = "Sub RunCmd()            " fullword ascii
   condition:
      uint16(0) == 0x8230 and filesize < 6KB and
      8 of them
}

rule aspx_gtonvbgidhh_webshell {
   meta:
      description = "6898 - file aspx_gtonvbgidhh.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "dc4186dd9b3a4af8565f87a9a799644fce8af25e3ee8777d90ae660d48497a04"
   strings:
      $s1 = "info.UseShellExecute = false;" fullword ascii
      $s2 = "info.Arguments = \"/c \" + command;" fullword ascii
      $s3 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s4 = "info.FileName = \"powershell.exe\";" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
      $s8 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
      $s9 = "result = result +  Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s10 = "ALAAAAAAAAAAA" fullword ascii /* base64 encoded string ',' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s12 = "var result = delimiter +  this.RunIt(Request.Params[\"exec_code\"]) + delimiter;" fullword ascii
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAA6AAAAAAAAAAAAAAA" ascii /* base64 encoded string ':' */
      $s14 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
      $s15 = "private string RunIt(string command)" fullword ascii
      $s16 = "Process process = Process.Start(info);" fullword ascii
      $s17 = "ProcessStartInfo info = new ProcessStartInfo();" fullword ascii
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii /* base64 encoded string ':' */
      $s19 = "6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s20 = "if (Request.Params[\"exec_code\"] == \"put\")" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}

rule aspx_qdajscizfzx_webshell {
   meta:
      description = "6898 - file aspx_qdajscizfzx.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "60d22223625c86d7f3deb20f41aec40bc8e1df3ab02cf379d95554df05edf55c"
   strings:
      $s1 = "info.FileName = \"cmd.exe\";" fullword ascii
      $s2 = "info.UseShellExecute = false;" fullword ascii
      $s3 = "info.Arguments = \"/c \" + command;" fullword ascii
      $s4 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
      $s8 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
      $s9 = "result = result +  Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s10 = "ALAAAAAAAAAAA" fullword ascii /* base64 encoded string ',' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s12 = "var result = delimiter +  this.RunIt(Request.Params[\"exec_code\"]) + delimiter;" fullword ascii
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAA6AAAAAAAAAAAAAAA" ascii /* base64 encoded string ':' */
      $s14 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
      $s15 = "private string RunIt(string command)" fullword ascii
      $s16 = "Process process = Process.Start(info);" fullword ascii
      $s17 = "ProcessStartInfo info = new ProcessStartInfo();" fullword ascii
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii /* base64 encoded string ':' */
      $s19 = "6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s20 = "if (Request.Params[\"exec_code\"] == \"put\")" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}

rule sig_6898_dcrypt {
   meta:
      description = "6898 - file dcrypt.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "02ac3a4f1cfb2723c20f3c7678b62c340c7974b95f8d9320941641d5c6fd2fee"
   strings:
      $s1 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s2 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s3 = "Prevents the user from cancelling during the installation process." fullword wide
      $s4 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s5 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
      $s6 = "/PASSWORD=password" fullword wide
      $s7 = "The Setup program accepts optional command line parameters." fullword wide
      $s8 = "Overrides the default component settings." fullword wide
      $s9 = "Specifies the password to use." fullword wide
      $s10 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
      $s11 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
      $s12 = "/DIR=\"x:\\dirname\"" fullword wide
      $s13 = "http://diskcryptor.org/                                     " fullword wide
      $s14 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
      $s15 = "HBPLg.sse" fullword ascii
      $s16 = "/LOG=\"filename\"" fullword wide
      $s17 = "Overrides the default folder name." fullword wide
      $s18 = "Overrides the default setup type." fullword wide
      $s19 = "Overrides the default directory name." fullword wide
      $s20 = "* AVz'" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "48aa5c8931746a9655524f67b25a47ef" and 15 of them )
}
