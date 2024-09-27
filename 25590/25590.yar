rule Py_Fuscate_Obfuscation {
    meta:
        description = "Detects Python scripts which could have been obfuscated through Py-Fuscate"
        author = "The DFIR Report"
        date = "2024-07-13"
        reference = "https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware"
    strings:
        $s1 = "import marshal,lzma,gzip,bz2,binascii,zlib;exec(marshal.loads("
    condition:
        $s1
}
