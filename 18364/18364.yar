rule case_18364_msi_attacker_email {
    meta:
        author      = "The DFIR Report"
        reference   = "https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours"
        description = "Detects potential MSI installers (such as Atera's) containing known attacker email addresses"
    
    strings:
        $email      = "edukatingstrong@polkschools.edu.org" nocase
    
    condition:
        uint32be(0) == 0xD0CF11E0 and uint32be(4) == 0xA1B11AE1 and $email
}
