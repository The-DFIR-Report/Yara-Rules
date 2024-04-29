/*
YARA Rule Set
Author: The DFIR Report
Date: 2024-04-23
Identifier: Case 23869
Reference: https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_23869_sysfunc_cmd {
	meta:
		creation_date = "2024-03-29"
		first_imported = "2024-03-29"
		last_modified = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "File generated dynamically from awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f3b211c45090f371869c396716972429896e0427da55ce8f1981787c2ea7eb0b"

	strings:
		$s1 = "@echo off" fullword
		$s2 = "DEL \"%~f0\"" fullword
		$s3 = "bcedit /set {default] bootstatuspolicy ignorereallifefailures" fullword
		$s4 = "bcedit /set {default] recoveryenabled no" fullword
		$s5 = "vssadmin delete shadows /all /quiet" fullword
		$s6 = "wmic shadowcopy /nointeractive" fullword
		$s7 = "wmic shadowcopy delete" fullword

	condition:
		all of them
}

rule case_23869_awscollector_ps1 {
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "e737831bea7ab9e294bf6b58ca193ba302b8869f5405aa6d3a6492d0334a04a6"

	strings:
		$author = "darussian@tutanota.com" fullword
		$s1 = "Locker" fullword
		$s2 = "Find-Remote-Executor" fullword
		$s3 = "lockerparams" fullword
		$s4 = "locker_cmd_list" fullword
		$s5 = "AWSCLIV2" fullword

	condition:
		$author or ( all of ($s*) )
}

rule case_23869_sysfunc_dll {
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "Description"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "b3942ead0bf76cf5f4baaa563b603fb6343009c324e3c862d16bbbbdcf482f1a"

	strings:
		$s1 = "gentlemen" fullword
		$s2 = "withdraw fang" fullword
		$s3 = "plants; mould, sympathize, elephant; associate" fullword
		$s4 = "blessing, defender; fashionable" fullword
		$s5 = "withdraw fang" fullword

	condition:
		all of them
}

rule case_23869_document_468 {
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "iceid loader"
		category = "MALWARE"
		malware = "iceid_loader"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f6e5dbff14ef272ce07743887a16decbee2607f512ff2a9045415c8e0c05dbb4"

	strings:
		$s1 = "quisquamEtVeniamOccaecati" fullword
		$s2 = "temporaImpeditQuiPraesentiumEligendiOptio" fullword
		$s3 = "fugiatSaepeQuiaPorroExplicaboExercitationemMaiores" fullword

	condition:
		all of them
}


rule case_23869_anydesk_ps1 {
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "anydesk install powershell script"
		category = "TOOL"
		malware = "anydesk"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "3064cecf8679d5ba1d981d6990058e1c3fae2846b72fa77acad6ab2b4f582dd7"

	strings:
		$s1 = "J9kzQ2Y0qO" fullword
		$s2 = "oldadministrator" fullword
		$s3 = "qc69t4B#Z0kE3" fullword
		$s4 = "anydesk.com"

	condition:
		all of them
}
