/*

   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-06-06
   Identifier: Case 12993 Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration
   Reference: https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/

*/

/* Rule Set ----------------------------------------------------------------- */

rule case_12993_cve_2021_44077_msiexec {
   meta:
      description = "Files - file msiexec.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
      date = "2022-06-06"
      hash1 = "4d8f797790019315b9fac5b72cbf693bceeeffc86dc6d97e9547c309d8cd9baf"
   strings:
      $x1 = "C:\\Users\\Administrator\\msiexec\\msiexec\\msiexec\\obj\\x86\\Debug\\msiexec.pdb" fullword ascii
      $x2 = "M:\\work\\Shellll\\msiexec\\msiexec\\obj\\Release\\msiexec.pdb" fullword ascii
      $s2 = "..\\custom\\login\\fm2.jsp" fullword wide
      $s3 = "Qk1QDQo8JUBwYWdlIGltcG9ydD0iamF2YS51dGlsLnppcC5aaXBFbnRyeSIlPg0KPCVAcGFnZSBpbXBvcnQ9ImphdmEudXRpbC56aXAuWmlwT3V0cHV0U3RyZWFtIiU+" wide
      $s4 = "Program" fullword ascii /* Goodware String - occured 194 times */
      $s5 = "Encoding" fullword ascii /* Goodware String - occured 809 times */
      $s6 = "base64EncodedData" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s8 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
      $s9 = "System" fullword ascii /* Goodware String - occured 2567 times */
      $s10 = "Base64Decode" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "$77b5d0d3-047f-4017-a788-503ab92444a7" fullword ascii
      $s12 = "  2021" fullword wide
      $s13 = "RSDSv_" fullword ascii
      $s14 = "503ab92444a7" ascii
      $s15 = "q.#z.+" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them

}

rule case_12993_cve_2021_44077_webshell {
   meta:
      description = "Files - file fm2.jsp"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
      date = "2022-06-06"
      hash1 = "8703f52c56b3164ae0becfc5a81bfda600db9aa6d0f048767a9684671ad5899b"
   strings:
      $s1 = "    Process powerShellProcess = Runtime.getRuntime().exec(command);" fullword ascii
      $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
      $s3 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
      $s4 = "out.println(\"<pre>\"+exec(request.getParameter(\"cmd\"))+\"</pre>\");" fullword ascii
      $s5 = "out.println(\"<tr \"+((i%2!=0)?\"bgcolor=\\\"#eeeeee\\\"\":\"\")+\"><td align=\\\"left\\\">&nbsp;&nbsp;<a href=\\\"javascript:ge" ascii
      $s6 = "out.println(\"<h1>Command execution:</h1>\");" fullword ascii
      $s7 = "    String command = \"powershell.exe \" + request.getParameter(\"cmd\");" fullword ascii
      $s8 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
      $s9 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
      $s10 = "static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
      $s11 = "            powerShellProcess.getErrorStream()));" fullword ascii
      $s12 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
      $s13 = "    // Executing the command" fullword ascii
      $s14 = ".getName()+\"\\\"><tt>download</tt></a></td><td align=\\\"right\\\"><tt>\"+new SimpleDateFormat(\"yyyy-MM-dd hh:mm:ss\").format(" ascii
      $s15 = "String out = exec(cmd);" fullword ascii
      $s16 = "static String exec(String cmd) {" fullword ascii
      $s17 = "            powerShellProcess.getInputStream()));" fullword ascii
      $s18 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fileName);" fullword ascii
      $s19 = "out.println(\"<pre>\"+auto(request.getParameter(\"url\"),request.getParameter(\"fileName\"),request.getParameter(\"cmd\"))+\"</p" ascii
      $s20 = "    powerShellProcess.getOutputStream().close();" fullword ascii
   condition:
      uint16(0) == 0x4d42 and filesize < 30KB and
      8 of them
}
