/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-09-01
Identifier: Case 5426 BazarLoader and the Conti Leaks
Reference: https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
*/

rule informational_AnyDesk_Remote_Software_Utility { 

   meta: 
      description = "files - AnyDesk.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "9eab01396985ac8f5e09b74b527279a972471f4b97b94e0a76d7563cf27f4d57" 
   strings: 
      $x1 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii 
      $s2 = "release/win_6.3.x" fullword ascii 
      $s3 = "16eb5134181c482824cd5814c0efd636" fullword ascii 
      $s4 = "b1bfe2231dfa1fa4a46a50b4a6c67df34019e68a" fullword ascii 
      $s5 = "Z72.irZ" fullword ascii 
      $s6 = "ysN.JTf" fullword ascii 
      $s7 = ",;@O:\"" fullword ascii 
      $s8 = "ekX.cFm" fullword ascii 
      $s9 = ":keftP" fullword ascii 
      $s10 = ">FGirc" fullword ascii 
      $s11 = ">-9 -D" fullword ascii 
      $s12 = "% /m_v?" fullword ascii 
      $s13 = "?\\+ X5" fullword ascii 
      $s14 = "Cyurvf7" fullword ascii 
      $s15 = "~%f_%Cfcs" fullword ascii 
      $s16 = "wV^X(P+ " fullword ascii 
      $s17 = "\\Ej0drBTC8E=oF" fullword ascii 
      $s18 = "W00O~AK_=" fullword ascii 
      $s19 = "D( -m}w" fullword ascii 
      $s20 = "avAoInJ1" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 11000KB and 
      1 of ($x*) and 4 of them 
} 

rule cobalt_strike_dll21_5426 { 
   meta: 
      description = "files - 21.dll" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "96a74d4c951d3de30dbdaadceee0956682a37fcbbc7005d2e3bbd270fbd17c98" 
   strings: 
      $s1 = "AWAVAUATVWUSH" fullword ascii 
      $s2 = "UAWAVVWSPH" fullword ascii 
      $s3 = "AWAVAUATVWUSPE" fullword ascii 
      $s4 = "UAWAVATVWSH" fullword ascii 
      $s5 = "AWAVVWUSH" fullword ascii 
      $s6 = "UAWAVAUATVWSH" fullword ascii 
      $s7 = "AVVWSH" fullword ascii 
      $s8 = "m1t6h/o*i-j2p2g7i0r.q6j3p,j2l2s7p/s9j-q0f9f,i7r2g1h*i8r5h7g/q9j4h*o7i4r9f7f3g*p/q7o1e5n8m1q4n.e+n0i*r/i*k2q-g0p-n+q7l3s6h-h6j*q/" ascii 
      $s9 = "s-e6m/f-g*j.i8p1g6j*i,o1s9o5f8r-p1l1k4o9n9l-s7q8g+n,f4t0q,f6n9q5s5e6i-f*e6q-r6g8s1o6r0k+h6p9i4f6p4s6l,g0p1j6l4s1l4h2f,s9p8t5t/g6" ascii 
      $s10 = "o1s1s9i2s.f1g5l6g5o2k8h*e9j2o3k0j1f+n,k9h5l*e8p*s2k5r3j-f5o-f,g+e*s-e9h7e.t0e-h3e2t1f8j5k/m9p6n/j3h9e1k3h.t6h2g1p.l*q8o*t9l6p4s." ascii 
      $s11 = "k7s9g7m5k4s5o3h6k.s1p.h9k.s-o8e*f5n9r,l4f-s5k3p2f/n1r.i*f*n-p4s3e7m9p2t/e3m5g1s9e0m1q/j*e*m-r*i+h.p9s2f6h-p5s6e2h8p1s*j.h3p-s.h0" ascii 
      $s12 = "k9g9o0t1s4k*k*h.s-p-k.h-m1k*f4h0j7f6n,i5g-n3h+l3n1j7j0e*n5r6r-i9i/e1q4m6i3e2o8j9h9e0m.r-i9m*t4j/r.o*l8m4i.t5l,g-h0p6f7l+p-l3l,g." ascii 
      $s13 = "s6k9n/j.s4s5g2p6s.k1t/j6s,s-g*p.n6f9m/g.n4n5j2q6n.f1p/g6n,n-j*q.m6e9o/h.m4m5i2r6m.e1p/h6m,m-i*r.p6h9m/e.p4p5l2s6p.h1l/e7p,p-l*s." ascii 
      $s14 = "r4k7g8t-k4o6m,o1s1k.k1s6o,h8k-s4j8q*m+f/i*q/f3m-r5j2n0f0i*q0m/e0j5q7n5f4j7q3n7f1m4g2s,g5s5l9h7s9p1o.t8k5r-j3t.k8h1t6r7m-l5h5t1l*" ascii 
      $s15 = "k8s9n7o9k5s5o9m2k0s1m3m.k,s-n+o-f9n9t+t6f4n5o6t2f0n1s/r1f-n-o.t*e8m9i-s6e4m5t3q5e1m1i5s.e,m-k0s*h8p9q7t9h5p5j8r2h0p1h+r.h,p-q+t-" ascii 
      $s16 = "o9g6g0l0s1e6h4p-g6s9s9p1m1k*s3l-t5s.f8m5r5f6n+i2j8f*h,p5j2r.h0h1q9i6e8r-i*n8m-r5s-l.i8f2i1k.o4n1t9l6l0g,p9j6f,g.l-j*n0o-t-l*p5s-" ascii 
      $s17 = "t8n2i3e0i,l.i7i9e8r1j7o0n3i9j0m3m-l6e6s9r*l6s5h4t6n7o*k.r1f+r4l/q9g7i3o.m+t9q*g/j0h0e1n*m3i,h.e4n3i5n-r9g1h2k6m7j,e,p3p+h2o4f/h4" ascii 
      $s18 = "[_^A^A_]" fullword ascii 
      $s19 = "k9s9f+j*k3s5o-j/k/s1h/p5k-s-o7j7f7n9t/g+f3n5q/r8f1n1t7g3f+n-p.g8e7m9s3q4e5m5o+h0e/m1g-h4e+m-m+q0h9p9f/e,h3p5l6e1h/p1o7t,h-p-k+f5" ascii 
      $s20 = "g8s9j0t4o,t+n3t1g0k9k1t,o5s0n+t9n6j+o0q2i4j6r1i3f,g+j2h1f2r1n-e9m,i2i7f3q4m-n7n4m.r.e1s*j,m5p/n0n6s8p9g/o7l3t+g.m.q.l7g6t,e-o/q." ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 2000KB and 
      8 of them 
} 

import "pe" 

rule cobalt_strike_exe21 { 
   meta: 
      description = "files -  21.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "972e38f7fa4c3c59634155debb6fb32eebda3c0e8e73f4cb264463708d378c39" 
   strings: 
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii 
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii 
      $s3 = "1brrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrr" ascii 
      $s4 = "\\hzA\\Vza\\|z%\\2z/\\3z\"\\/z%\\/z8\\9z\"\\(zl\\3z\"\\9z4\\5z8\\|z.\\9z+\\5z\"\\qz)\\2z(\\|z:\\=z>\\5z-\\>z \\9z?\\QzF\\\\zL\\" fullword ascii 
      $s5 = "\\zL\\/z>\\qz.\\=za\\0z-\\(z\"\\\\zL\\/z>\\qz?\\,za\\?z5\\.z \\\\zL\\/z>\\qz?\\,za\\0z-\\(z\"\\\\zL\\/z:\\qz*\\5zL\\\\zL\\/z:\\q" ascii 
      $s6 = "\\zL:\\zL" fullword ascii 
      $s7 = "\\\\z:\\\\z" fullword ascii 
      $s8 = "\\qz/\\3z!\\,z%\\0z)\\8zl\\tzc\\?z \\.ze\\|z*\\)z\"\\?z8\\5z#\\2zl\\:z>\\3z!\\|z-\\|z\"\\=z8\\5z:\\9zl\\?z#\\2z?\\(z>\\)z/\\(z#" ascii 
      $s9 = "qz<\\%zL\\\\zL\\9z?\\qz?\\*zL\\\\zL\\9z?\\qz9\\%zL\\\\zL\\9z?\\qz:\\9zL\\\\zL\\9z8\\qz)\\9zL\\\\zL\\9z9\\qz)\\/zL\\\\zL\\:z-\\qz" ascii 
      $s10 = "zL\\\\zL\\0z:\\qz" fullword ascii 
      $s11 = "z-\\(z\"\\\\zL\\/z:\\qz" fullword ascii 
      $s12 = "  VirtualProtect failed with code 0x%x" fullword ascii 
      $s13 = "3\\)z'\\\\zL\\>z)\\\\zL\\/z \\\\zL\\9z8\\\\zL\\0z:\\\\zL\\0z8\\\\zL\\:z-\\\\zL\\*z%\\\\zL\\4z5\\\\zL\\=z6\\\\zL\\9z9\\\\zL\\1z'" ascii 
      $s14 = "z#\\\\zL\\,z \\\\zL\\,z8\\\\zL\\.z#\\\\zL\\.z9\\\\zL\\4z>\\\\zL\\/z'\\\\zL\\/z=\\\\zL\\/z:\\\\zL\\(z$\\\\zL\\(z>\\\\zL\\)z>\\\\z" ascii 
      $s15 = "qz \\5zL\\\\zL\\8z)\\qz \\)zL\\\\zL\\8z%\\*za\\1z:\\\\zL\\9z \\qz+\\.zL\\\\zL\\9z\"\\qz-\\)zL\\\\zL\\9z\"\\qz.\\&zL\\\\zL\\9z\"" ascii 
      $s16 = "qz<\\7zL\\\\zL\\)z6\\qz9\\&za\\?z5\\.z \\\\zL\\)z6\\qz9\\&za\\0z-\\(z\"\\\\zL\\*z%\\qz:\\2zL\\\\zL\\$z$\\qz6\\=zL\\\\zL\\&z$\\qz" ascii 
      $s17 = "qz'\\.zL\\\\zL\\7z5\\qz'\\;zL\\\\zL\\0z8\\qz \\(zL\\\\zL\\0z:\\qz \\*zL\\\\zL\\1z%\\qz\"\\&zL\\\\zL\\1z'\\qz!\\7zL\\\\zL\\1z \\q" ascii 
      $s18 = "]zL\\=z*\\qz6\\=zL\\\\zL\\=z>\\qz-\\9zL\\\\zL\\=z>\\qz.\\4zL\\\\zL\\=z>\\qz(\\&zL\\\\zL\\=z>\\qz)\\;zL\\\\zL\\=z>\\qz%\\-zL\\\\z" ascii 
      $s19 = "  Unknown pseudo relocation protocol version %d." fullword ascii 
      $s20 = "\\L*L\\]qN\\WHKl]qO\\W{j\\XJL\\][G\\}" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash()=="17b461a082950fc6332228572138b80c" or  
8 of them) 
} 

rule informational_NtdsAudit_AD_Audit_Tool { 
   meta: 
      description = "files - NtdsAudit.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "fb49dce92f9a028a1da3045f705a574f3c1997fe947e2c69699b17f07e5a552b" 
   strings: 
      $x1 = "WARNING: Use of the --pwdump option will result in decryption of password hashes using the System Key." fullword wide 
      $s2 = "costura.nlog.dll.compressed" fullword wide 
      $s3 = "costura.microsoft.extensions.commandlineutils.dll.compressed" fullword wide 
      $s4 = "Password hashes have only been dumped for the \"{0}\" domain." fullword wide 
      $s5 = "The NTDS file contains user accounts with passwords stored using reversible encryption. Use the --dump-reversible option to outp" wide 
      $s6 = "costura.system.valuetuple.dll.compressed" fullword wide 
      $s7 = "TargetRNtdsAudit.NTCrypto.#DecryptDataUsingAes(System.Byte[],System.Byte[],System.Byte[])T" fullword ascii 
      $s8 = "c:\\Code\\NtdsAudit\\src\\NtdsAudit\\obj\\Release\\NtdsAudit.pdb" fullword ascii 
      $s9 = "NtdsAudit.exe" fullword wide 
      $s10 = "costura.esent.interop.dll.compressed" fullword wide 
      $s11 = "costura.costura.dll.compressed" fullword wide 
      $s12 = "costura.registry.dll.compressed" fullword wide 
      $s13 = "costura.nfluent.dll.compressed" fullword wide 
      $s14 = "dumphashes" fullword ascii 
      $s15 = "The path to output hashes in pwdump format." fullword wide 
      $s16 = "Microsoft.Extensions.CommandLineUtils" fullword ascii 
      $s17 = "If you require password hashes for other domains, please obtain the NTDS and SYSTEM files for each domain." fullword wide 
      $s18 = "microsoft.extensions.commandlineutils" fullword wide 
      $s19 = "-p | --pwdump <file>" fullword wide 
      $s20 = "get_ClearTextPassword" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 2000KB and 
      1 of ($x*) and 4 of them 
} 

rule informational_AdFind_AD_Recon_and_Admin_Tool {
   meta: 
      description = "files - AdFind.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682" 
   strings: 
      $s1 = "   -sc dumpugcinfo         Dump info for users/computers that have used UGC" fullword ascii 
      $s2 = "   -sc computers_pwdnotreqd Dump computers set with password not required." fullword ascii 
      $s3 = "   -sc computers_inactive  Dump computers that are disabled or password last set" fullword ascii 
      $s4 = "   -sc computers_active    Dump computers that are enabled and password last" fullword ascii 
      $s5 = "   -sc ridpool             Dump Decoded Rid Pool Info" fullword ascii 
      $s6 = "      Get top 10 quota users in decoded format" fullword ascii 
      $s7 = "   -po           Print options. This switch will dump to the command line" fullword ascii 
      $s8 = "ERROR: Couldn't properly encode password - " fullword ascii 
      $s9 = "   -sc users_accexpired    Dump accounts that are expired (NOT password expiration)." fullword ascii 
      $s10 = "   -sc users_disabled      Dump disabled users." fullword ascii 
      $s11 = "   -sc users_pwdnotreqd    Dump users set with password not required." fullword ascii 
      $s12 = "   -sc users_noexpire      Dump non-expiring users." fullword ascii 
      $s13 = "    adfind -default -rb ou=MyUsers -objfilefolder c:\\temp\\ad_out" fullword ascii 
      $s14 = "      Dump all Exchange objects and their SMTP proxyaddresses" fullword ascii 
      $s15 = "WLDAP32.DLL" fullword ascii 
      $s16 = "AdFind.exe" fullword ascii 
      $s17 = "                   duration attributes that will be decoded by the -tdc* switches." fullword ascii 
      $s18 = "   -int8time- xx Remove attribute(s) from list to be decoded as int8. Semicolon delimited." fullword ascii 
      $s19 = "replTopologyStayOfExecution" fullword ascii 
      $s20 = "%s: [%s] Error 0x%0x (%d) - %s" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 4000KB and 
      8 of them 
}
