import "pe"

rule case_19172_trigona {
   meta:
      description = "19172 - Trigona ransomware"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/"
      date = "2024-01-26"
      hash1 = "d743daa22fdf4313a10da027b034c603eda255be037cb45b28faea23114d3b8a"
   strings:
      $delphi = "Delphi" fullword ascii
      $run_key = "software\\microsoft\\windows\\currentversion\\run" fullword wide
      $ransom_note = "how_to_decrypt.hta" fullword wide
   condition:
       pe.is_pe and all of them
}
