/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2025-02-20
   Identifier: Case 27244
   Reference: https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_27244_metasploit_hta_stager {
   meta:
      description = "file UsySLX1n.hta"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/"
      date = "2025-02-20"
      hash1 = "192325984bfec886dda91f8b3f02e5d5b4e9ff9f5a28753fb578593b24893ffc"
   strings:
      $s1 = "CreateObject(\"Wscript.Shell\")" ascii
      $s2 = "ExpandEnvironmentStrings(\"%PSModulePath%\")" ascii
      $s3 = "(path + \"\\..\\powershell.exe\")" ascii
      $s4 = "powershell.exe -nop -w hidden -e" ascii
      $s5 = "<script language=\"VBScript\">" ascii
      $s6 = "aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkA" ascii /* base64 encoded string 'if([IntPtr]::Size -eq 4)' */
   condition:
      uint16(0) == 0x733c and filesize < 20KB and
      all of them
}
