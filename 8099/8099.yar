/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2021-12-12
   Identifier: Case 8099 Diavol Ransomware
   Reference: https://thedfirreport.com/2021/12/13/diavol-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule uvvfvnnswte {
   meta:
      description = "8099 - file uvvfvnnswte.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "5551fb5702220dfc05e0811b7c91e149c21ec01e8ca210d1602e32dece1e464d"
   strings:
      $s1 = "(s#u%x0m(m#n&y*r$o&k\"j*o$y&x\"k)l#k%y!l)y#u%j0m%v0w)w.n%k0q)l.o&p/s*m-p&u/m*v.q+j%o&s%r+w%y&p%s,t&k%q&t,q&u%r'u,n%w%o%v,s%q%t%w" ascii
      $s2 = "0w(r#v%l0j(l$u\"o*u$n&p\"v*p$x&k!q)k#j%r!x)v#t,y.k%y0v)t.r%l0p)w-m&o/r*n-t&r/l)m%w+m%n&x%n+x%x&s&y,s&j%j&p,n&t(q%s,q%v%l%j,t%p%o" ascii
      $s3 = "%r0v(y#p%k0k'w&m\"p*t$m&v\"y*q$k%w!n)j#q%l!w)w.o)y.l%x0u)j.u%m0s*k-j&n/y*x-s&s0w&u%x+l%m&n%q+y%k%o&v,r&q%t&o,o'o%q%t,p%u%r%m,u%s" ascii
      $s4 = "#t%s0u(j#o%j/x$p&j\"q*w$v&y\"x*r#l%x!o)q#r%k!v(l0x)v.m%s0n)m.t%v/t*l-k&m/j*w-r%p%p&r%y+o%v&q%p+j&l%p&w,y&r%s&n)t%x%n%u,k%n%u%l,n" ascii
      $s5 = "#s+r+y+x/o#k,q$l$t%q0x$u.s*j,s0l(r&r,u0y*p%s!y-y%v'l&v%l%o-q+o%s!k-m)l!p-n!r(q(l.t)p\"o+s%k&v'j*v#w&y/n&q&w&v'm)s\"r#n/v*w/j*l\"" ascii
      $s6 = "%y&u&x!s%k%t%j%m\"p&m&k%o%n\"m%l&v%t%s\"r%q&u%y,l/o)u+p0q)y)p)q)r-y)m+x-o,u,t/u*s,n+l+k0j,t,m+q+t0w,o,x+v+y0t,y)o*k*j-q*x)j*p*o-" ascii
      $s7 = "-r#u&p.w+l#r,o%w%x%y$n%y-j,u$y(y,s,r,y$w%n-n%v-q)l%l%q%p-r!o/n+k\"r,q)q#r!s(o%l#p&s\"r.n*q&q.k*u#y+s\"j(n*o\"o)w*t)s%k#r/l,w#w'u" ascii
      $s8 = ",j/j#t(v+l#s.s%w%x%y0x$o%v%u-x,j0t$j/m+n%l$k!k\"l+t-q!p-x&y+v/l%q%s%r0n'v%w%v&m,u$w+y+r+s*s*r*q*p*o*n*m*l*k*j+y+x+w+v+u+t+s!l!w'" ascii
      $s9 = ",n0m%s$s(j0n(q#m*v0p.x0q't0w)v)x)y/m-s(y%o&m%n,w0t/l#x(r*k+p)k%p0k,v(k$w!t%j*w#x,k(o!y%y#w,j\"l&s(w%r!n*t0l0p%v#y+p+s)q%o%p$m'j0" ascii
      $s10 = "(l/j#l0u$t/n$x0y!p0n$v(k&w,p,t,t,s$w(y-u*u!o,q%m%k%j,r&m0l.s%t%t,p)u-v,o&s$j)s+w%n0l-t&q&o/w%y&t&s&r.n)x,o)t.p*w*x)u%y/m*m\"j'j#" ascii
      $s11 = "/k#u'u)x0l'y(y0t$l&v*y%s+j$t#p,t,s$w(y-u,o%m&p0p.w%j%q+w%q(q)u-y)s$v%m-o)o+n!l-t+x+y.n*x+t,y&s's*s\"j.v*t(o*y+y#t/l)v%y&o,q*u(x$" ascii
      $s12 = "&q+v.s)m/v#y%w,q,x$o/q,q,o,n,n!n0n.y0u$o%t%m)t%w-o%p%p%p%o,u)l%o-v(k%x%x%w)u\"p)o+x+x&q&p,v+u&u&t&s.m&n\"u.p*u&j,j)s0p+o*s*t#v/x" ascii
      $s13 = "+s+r/q*o*j0l,y,j,k-n+w0x$r,k.x,p,u,r0q)o%o-r%w-k(x%j$l%y!w-y)n+l$p\"q%y%x.w0o&y&l&k&j,y0x%q&n&u\"l.l*m,q)x*y+m*v#t/t$v%m&x#w/q+y" ascii
      $s14 = "+s%j/t)s+w+v(y!u,j,j,q,p&w)x*v,t,s(n(m0p$p,s,x+p%m%j)n!x-x%k,p+x%u%r!m#w)y!k&j*l\"m&y%q&l*o\"v.j*u+t&q#j&y*x*j+y#t/l)v&y/w,n#v/p" ascii
      $s15 = "/v*u'y*w(y*y(t&t-x%y%r%s0w$q(y)l(t(n(m0p$x&j'u0u&p%j%q%p+w\"n)l%t%s-w)y$t%t0o&p&l&k&j*t(y\"n/v&t&t&s&r/o%s&s&v+m#m/v#r'p)x#t*t*n" ascii
      $s16 = "'s%k/m&k&l&m0u$s(m0s*n(n0v)y(r-w,y%u,j.k,y&q'r!t-t)t%r\"k)o!o0l&t%s%r%y!x-q*u$o&w#l)r&p&s/u*p$w&o'm(r*y&k.s)x\"q'q#s*y+p/v(n#w*n" ascii
      $s17 = "\"k+m+y+x+w'y(y0t$l&v*y0t$x(w$j0m-s&j(l%k%l%m-p)l$n&p!x#o!n$n!q-q&v\"t%j%t%w!o.r*u\"s*k,q&k\"q+u%y%t\"k.u*u(p*x*j+y#t/r$v%m'x#w/" ascii
      $s18 = "(k%m+w*w(p#s'r-p+n&r0t-o%t%u$l+l&k!x-v%k%l(u%m%u%k%j%q-o)x,u-j)o+k't,j,k,l-q*j,s%l,r-t#o+t+u*v&t&j&r&y&x,o/p\"t*w*x/m+y*s#w/y$q%" ascii
      $s19 = "$t#j/v)l%w#n0j!u'k(j$y0w+v!j%r%s,j%k(n!j's%y.k%t)t%m\"q0s-n)q#y!r!s%j)l&v!s$q\"r'x0y&r*v&w!o0v)x!v\"r\"r&q*w(x!v#m+k!l#j+n%o#k#n" ascii
      $s20 = "#t%n)y/q#p(n$r%j0r)u(y-l+o0v$j's&k)t&q%k%l$s)m%w-n0l%q%p%o0v.r'x!j.t,r+j-j(j%o.s%l*k+r&l+t*p.j*w*r,j%j&w+o&y,n&u$l'n\"t(p#w/y+j)" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "1a4ea0d6f08424c00bbeb4790cdf1ca7" and ( pe.exports("GhlqallxvchxEpmvydvyzqt") and pe.exports("PyflzyhnwVkaNixwdqktzn") ) or 8 of them )
}

rule files_Rubeus {
   meta:
      description = "8099 - file Rubeus.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "0e09068581f6ed53d15d34fff9940dfc7ad224e3ce38ac8d1ca1057aee3e3feb"
   strings:
      $x1 = "        Rubeus.exe dump [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM] [/nowrap]" fullword wide
      $x2 = "        Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH" wide
      $x3 = "[!] GetSystem() - OpenProcessToken failed!" fullword wide
      $x4 = "        Rubeus.exe createnetonly /program:\"C:\\Windows\\System32\\cmd.exe\" [/show]" fullword wide
      $x5 = "[!] GetSystem() - ImpersonateLoggedOnUser failed!" fullword wide
      $x6 = "[X] You need to have an elevated context to dump other users' Kerberos tickets :( " fullword wide
      $x7 = "[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'" fullword wide
      $x8 = "    Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:" fullword wide
      $s9 = "Z:\\Agressor\\github.com-GhostPack\\Rubeus-master\\Rubeus\\obj\\Debug\\Rubeus.pdb" fullword ascii
      $s10 = "    Triage all current tickets (if elevated, list for all users), optionally targeting a specific LUID, username, or service:" fullword wide
      $s11 = "[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi" fullword wide
      $s12 = "Action: Dump Kerberos Ticket Data (All Users)" fullword wide
      $s13 = "[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'" fullword wide
      $s14 = "[*] Listing statistics about target users, no ticket requests being performed." fullword wide
      $s15 = "[X] OpenProcessToken error: {0}" fullword wide
      $s16 = "[X] CreateProcessWithLogonW error: {0}" fullword wide
      $s17 = "[*] Target service  : {0:x}" fullword wide
      $s18 = "[*] Target Users           : {0}" fullword wide
      $s19 = "        Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.K" wide
      $s20 = "    List all current tickets in detail (if elevated, list for all users), optionally targeting a specific LUID:" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule SharedFiles {
   meta:
      description = "8099 - file SharedFiles.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "c17e71c7ae15fdb02a4e22df4f50fb44215211755effd6e3fc56e7f3e586b299"
   strings:
      $s1 = "ButtonSkin.dll" fullword wide
      $s2 = "MyLinks.dll" fullword wide
      $s3 = "DragListCtrl.dll" fullword ascii
      $s4 = "whoami.exe" fullword ascii
      $s5 = "constructor or from DllMain." fullword ascii
      $s6 = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s7 = "kLV -{T" fullword ascii
      $s8 = "CtrlList1" fullword wide
      $s9 = "CtrlList2" fullword wide
      $s10 = "CtrlList3" fullword wide
      $s11 = "wox)YytbACl_<me*y3X(*lNCvY@8jsbePLfVHH!X2p2TdHa6+1hoo^1N7gNtwhki)Lbaso@*ne7" fullword ascii
      $s12 = "QX[gbL" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "BasicScore" fullword ascii
      $s14 = ".?AVCDemoDlg@@" fullword ascii
      $s15 = "jLDfSektRC2FrOiWNzhbH3AsmBEIwg1U" fullword ascii
      $s16 = "9t$xt5" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "DeAj1=n" fullword ascii
      $s18 = "WmaK|IG" fullword ascii
      $s19 = "oTRHz`R" fullword ascii
      $s20 = "VWATAUAVAWLc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "c270086ea8ef591ab09b6ccf85dc6072" and pe.exports("BasicScore") or 8 of them )
}

rule new_documents_2005_iso {
   meta:
      description = "8099 - file new-documents-2005.iso"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-11-29"
      hash1 = "1de1336e311ba4ab44828420b4f876d173634670c0b240c6cca5babb1d8b0723"
   strings:
      $x1 = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = "SHAREDFI.DLL" fullword ascii
      $s4 = "SharedFiles.dll" fullword wide
      $s5 = "C:\\Users\\User\\Documents" fullword wide
      $s6 = "DragListCtrl.dll" fullword ascii
      $s7 = "MyLinks.dll" fullword wide
      $s8 = "ButtonSkin.dll" fullword wide
      $s9 = "whoami.exe" fullword ascii
      $s10 = " ..\\Windows\\System32\\rundll32.exe" fullword wide
      $s11 = "User (C:\\Users)" fullword wide
      $s12 = "        " fullword ascii
      $s13 = "DOCUMENT.LNK" fullword ascii
      $s14 = "Documents.lnk@" fullword wide
      $s15 = ",System32" fullword wide
      $s16 = " Type Descriptor'" fullword ascii
      $s17 = " constructor or from DllMain." fullword ascii
      $s18 = "  " fullword ascii
      $s19 = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s20 = " Class Hierarchy Descriptor'" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule files_tmp {
   meta:
      description = "8099 - file tmp.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "493a1fbe833c419b37bb345f6f193517d5d9fd2577f09cc74b48b49d7d732a54"
   strings:
      $s1 = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongFilenameTooLongTooManyLinksCrossesDevicesDeadlockExecuta" ascii
      $s2 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longfilename " ascii
      $s3 = "kuiiqaiusmlytqxxnrtl.dll" fullword ascii
      $s4 = "Node.js API crypto.randomFillSync is unavailableNode.js crypto module is unavailablerandSecure: VxWorks RNG module is not initia" ascii
      $s5 = "ctoryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection" ascii
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s7 = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
      $s8 = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
      $s9 = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
      $s10 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
      $s11 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
      $s12 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
      $s13 = "rno: did not return a positive valuegetrandom: this target is not supportedC:ehpgbcedommleqfhulhfnkiqvffztwzvxtvorsmuwrtkmtsqdfl" ascii
      $s14 = "attempted to zero-initialize type `(*mut u8, unsafe extern \"C\" fn(*mut u8))`, which is invalidassertion failed: 0 < pointee_si" ascii
      $s15 = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
      $s16 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
      $s17 = "workFileHandleFilesystemLoopReadOnlyFilesystemDirectoryNotEmptyIsADirectoryNotADirectoryWouldBlockAlreadyExistsBrokenPipeNetwork" ascii
      $s18 = "abortednetwork unreachablehost unreachableconnection resetconnection refusedpermission deniedentity not foundErrorkind" fullword ascii
      $s19 = "thread panicked while processing panic. aborting." fullword ascii
      $s20 = "internal_codedescription0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "59e16a2afa5b682bb9692bac873fa10c" and ( pe.exports("EnterDll") and pe.exports("alpjxriee") and pe.exports("arcfqsbobtwbjrf") and pe.exports("asblsmvdudmlwht") and pe.exports("bgttsajxwgwrsai") and pe.exports("bosaplw") ) or 8 of them )
}

rule Documents {
   meta:
      description = "8099 - file Documents.lnk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "e87f9f378590b95de1b1ef2aaab84e1d00f210fd6aaf5025d815f33096c9d162"
   strings:
      $x1 = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
      $x2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = "C:\\Users\\User\\Documents" fullword wide
      $s4 = " ..\\Windows\\System32\\rundll32.exe" fullword wide
      $s5 = "User (C:\\Users)" fullword wide
      $s6 = ",System32" fullword wide
      $s7 = "Documents" fullword wide /* Goodware String - occured 89 times */
      $s8 = "windev2106eval" fullword ascii
      $s9 = "%Windows" fullword wide /* Goodware String - occured 2 times */
      $s10 = "OwHUSx" fullword ascii
      $s11 = "System Folder" fullword wide /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x004c and filesize < 3KB and
      1 of ($x*) and all of them
}
