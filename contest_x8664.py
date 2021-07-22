#!/usr/bin/env python3

import os
from abc import ABC

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.mapper import QlFsMappedObject
import struct


class BaseChallenge:
    @staticmethod
    def apply(ql):
        raise NotImplementedError()


class Chal1(BaseChallenge):
    """
    simple mapping and storing value
    """
    @staticmethod
    def apply(ql):
        ql.mem.map(0x1000, 0x1000, info="Challenge 1")
        ql.mem.write(0x1337, struct.pack("<i", 1337))


class Chal2(BaseChallenge):
    """
    inspired by qiling/qiling/os/posix/syscall/utsname.py using set_syscall
    """
    @staticmethod
    def uname_patch(ql, address, *args, **kw):
        """ https://man7.org/linux/man-pages/man2/uname.2.html
        struct utsname {
               char sysname[];    /* Operating system name (e.g., "Linux") */
               char nodename[];   /* Name within "some implementation-defined
                                     network" */
               char release[];    /* Operating system release
                                     (e.g., "2.6.28") */
               char version[];    /* Operating system version */
               char machine[];    /* Hardware identifier */
           #ifdef _GNU_SOURCE
               char domainname[]; /* NIS or YP domain name */
           #endif
           };
        """
        buf = b''
        buf += b'QilingOS\x00'.ljust(65, b'\x00')
        buf += b'ql_vm'.ljust(65, b'\x00')
        buf += b'99.0-RELEASE'.ljust(65, b'\x00')
        buf += b'ChallengeStart'.ljust(65, b'\x00')
        buf += b'ql_processor'.ljust(65, b'\x00')
        buf += b'\\disasm.me'.ljust(65, b'\x00')
        ql.mem.write(address, buf)
        regreturn = 0
        return regreturn

    @staticmethod
    def apply(ql):
        ql.set_syscall('uname', Chal2.uname_patch)


class Chal3(BaseChallenge):
    """
    inspired by qiling/examples/hello_x86_linux_fake_urandom.py using add_fs_mapper
    the second solution is to set_syscall open+read to modify values got from /dev/urandom handle


fd = open("/dev/urandom", 0);
read(fd, buf, 0x20uLL); // read 32 bytes
read(fd, &v5, 1uLL); // read 33th byte - every of first 32 bytes must be different from the last one
close(fd);
/*
https://man7.org/linux/man-pages/man2/getrandom.2.html - reads from /dev/urandom
BUT qiling implementation uses os.urandom - qiling/qiling/os/posix/syscall/random.py
WHY?
*/
getrandom(v7, 32LL, 1LL);
v2 = 0;
for ( i = 0; i <= 31; ++i )
        if ( buf[i] == v7[i] && buf[i] != v5 )
          ++v2;
if ( v2 == 32 )
    *a1 = 1;
    """

    class FakeUrandom(QlFsMappedObject, ABC):
        def read(self, size):
            if size == 1:
                return b"\xff"
            return bytes(size)

        def fstat(self):
            return -1

        def close(self):
            return 0

    @staticmethod
    def getrandom_patch(ql, buf, buflen, flags, *args, **kw):

        ql.log.warning(f"> getrandom_patch({ql}, {buf}, {buflen}, {flags})")
        rnd = Chal3.FakeUrandom.read(None, buflen)
        print(rnd)
        ql.mem.write(buf, rnd)
        
        return len(rnd)

    @staticmethod
    def apply(ql):
        ql.set_syscall('getrandom', Chal3.getrandom_patch)
        ql.add_fs_mapper("/dev/urandom", Chal3.FakeUrandom())


class Chal4(BaseChallenge):
    """
.text:0000000000000E40                   loc_E40:
.text:0000000000000E40 8B 45 F8          mov     eax, [rbp+var_8]
.text:0000000000000E43 39 45 FC          cmp     [rbp+var_4], eax ; Compare Two Operands
.text:0000000000000E46 7C ED             jl      short loc_E35   ; Jump if Less (SF!=OF)



.text:0000000000000E35                   loc_E35:
.text:0000000000000E35 48 8B 45 E8       mov     rax, [rbp+var_18]
.text:0000000000000E39 C6 00 01          mov     byte ptr [rax], 1
.text:0000000000000E3C 83 45 FC 01       add     [rbp+var_4], 1  ; Add

This way we should make var4 < var8

There are at least 4 ways to solve this challenge:
1. Patch 0xe46 - jl to jg
2. Patch 0xe43 - replace "cmp     [rbp+var_4], eax" to "cmp     eax, [rbp+var_4]"
3. Patch 0xe3c - add to var_8
4. Good way - hook_address to change registry

The 4th method is good if we have some integrity checks of code section, so we will use it
    """
    @staticmethod
    def check_pass(ql: Qiling):
        ql.mem.write(ql.reg.rbp-8, struct.pack("<i", 5))

    @staticmethod
    def apply(ql):
        ql.hook_address(Chal4.check_pass, 0x0000555555554000 + 0xe40)


class Chal5(BaseChallenge):
    @staticmethod
    def srand_patch(ql, seed, *args, **kw):
        return 0

    @staticmethod
    def rand_patch(ql, *args, **kw):
        print("RAND PATCH")
        return 0

    @staticmethod
    def apply(ql):
        pass
        # idk the reason but my srand wants to execute from libc.so instead of redefined srand
        # ql.set_syscall("srand", Chal5.srand_patch) or ql.set_api("srand", Chal5.srand_patch)
        # so i just nop-ped this call
        ql.patch(0xe70, b"\x90" * 7)
        # so do rand does not work too, we will patch them
        # ql.set_api("rand", Chal5.rand_patch)
        ql.patch(0xe8d, b"\xb8\x00\x00\x00\x00") # exact 5 bytes to rewrite "call _rand" to "mov eax, 0"


class Chal6(BaseChallenge):
    """
.text:0000000000000E40                   loc_E40:
.text:0000000000000E40 8B 45 F8          mov     eax, [rbp+var_8]
.text:0000000000000E43 39 45 FC          cmp     [rbp+var_4], eax ; Compare Two Operands
.text:0000000000000E46 7C ED             jl      short loc_E35   ; Jump if Less (SF!=OF)



.text:0000000000000E35                   loc_E35:
.text:0000000000000E35 48 8B 45 E8       mov     rax, [rbp+var_18]
.text:0000000000000E39 C6 00 01          mov     byte ptr [rax], 1
.text:0000000000000E3C 83 45 FC 01       add     [rbp+var_4], 1  ; Add

This way we should make var4 < var8

There are at least 4 ways to solve this challenge:
1. Patch 0xe46 - jl to jg
2. Patch 0xe43 - replace "cmp     [rbp+var_4], eax" to "cmp     eax, [rbp+var_4]"
3. Patch 0xe3c - add to var_8
4. Good way - hook_address to change registry

The 4th method is good if we have some integrity checks of code section, so we will use it
    """
    @staticmethod
    def jnz_pass(ql: Qiling):
        print("Change reg")
        ql.reg.ef ^= 1 << 6

    @staticmethod
    def apply(ql):
        #ql.hook_address(Chal6.jnz_pass, 0x0000555555554000 + 0xF18)
        #ql.hook_address(Chal6.jnz_pass, 0x0000555555554000 + 0xF16)
        ql.patch(0xF18, b"\x74") # jnz - jz
        pass


class Chal7(BaseChallenge):
    """
    Redefining is not interesting anymore (too many challenges solved this way), so patch param of sleep :)
    """
    @staticmethod
    def apply(ql):
        ql.patch(0xF37, b"\xBF\x00\x00\x00\x00") #  mov edi, 0FFFFFFFFh -> mov edi, 0
        pass


class Chal8(BaseChallenge):
    """
.text:0000000000000F44 55                                push    rbp
.text:0000000000000F45 48 89 E5                          mov     rbp, rsp
.text:0000000000000F48 48 83 EC 20                       sub     rsp, 20h        ; Integer Subtraction
.text:0000000000000F4C 48 89 7D E8                       mov     [rbp+var_18], rdi
.text:0000000000000F50 BF 18 00 00 00                    mov     edi, 18h        ; size
.text:0000000000000F55 E8 A6 FA FF FF                    call    _malloc         ; Call Procedure
.text:0000000000000F5A 48 89 45 F8                       mov     [rbp+var_8], rax
.text:0000000000000F5E BF 1E 00 00 00                    mov     edi, 1Eh        ; size
.text:0000000000000F63 E8 98 FA FF FF                    call    _malloc         ; Call Procedure
.text:0000000000000F68 48 89 C2                          mov     rdx, rax
.text:0000000000000F6B 48 8B 45 F8                       mov     rax, [rbp+var_8]
.text:0000000000000F6F 48 89 10                          mov     [rax], rdx
.text:0000000000000F72 48 8B 45 F8                       mov     rax, [rbp+var_8]
.text:0000000000000F76 C7 40 08 39 05 00+                mov     dword ptr [rax+8], 539h
.text:0000000000000F76 00
.text:0000000000000F7D 48 8B 45 F8                       mov     rax, [rbp+var_8]
.text:0000000000000F81 F3 0F 10 05 0F 0B+                movss   xmm0, cs:dword_1A98 ; Move Scalar Single-FP
.text:0000000000000F81 00 00
.text:0000000000000F89 F3 0F 11 40 0C                    movss   dword ptr [rax+0Ch], xmm0 ; Move Scalar Single-FP
.text:0000000000000F8E 48 8B 45 F8                       mov     rax, [rbp+var_8]
.text:0000000000000F92 48 8B 00                          mov     rax, [rax]
.text:0000000000000F95 48 B9 52 61 6E 64+                mov     rcx, 64206D6F646E6152h
.text:0000000000000F95 6F 6D 20 64
.text:0000000000000F9F 48 89 08                          mov     [rax], rcx
.text:0000000000000FA2 C7 40 08 61 74 61+                mov     dword ptr [rax+8], 617461h
.text:0000000000000FA2 00
.text:0000000000000FA9 48 8B 45 F8                       mov     rax, [rbp+var_8]
.text:0000000000000FAD 48 8B 55 E8                       mov     rdx, [rbp+var_18]
.text:0000000000000FB1 48 89 50 10                       mov     [rax+10h], rdx
.text:0000000000000FB5 90                                nop                     ; No Operation
.text:0000000000000FB6 C9                                leave                   ; High Level Procedure Exit
.text:0000000000000FB7 C3                                retn
    """
    @staticmethod
    def struct_work(ql):
        print("CHAL 8")
        mread = lambda addr: ql.mem.read(addr, 8)
        munpack = lambda value: struct.unpack("<q", value)[0]

        print("Expecting to see part of 'Random value'")
        print(">", mread(munpack(mread(ql.reg.rax))))

        print("Expecting to see first two bytes of 1337 (539h) - upper DWORD, and 3DFCD6EA - lower DWORD")
        print(">", hex( munpack(mread(ql.reg.rax+8))))

        return 0

    @staticmethod
    def apply(ql):
        # Challenge 8: Unpack the struct and write at the target address.

        """
        So, the struct is
        {
        _DWORD mmap0;
        _DWORD mmap1;
        _DWORD leet_val;
        _DWORD some_magic;
        }
        """
        ql.hook_address(Chal8.struct_work, ql.base + 0xFB7)


class Chal9(BaseChallenge):
    @staticmethod
    def tolower_patch(ql, *args, **kwargs):
        # just mock it to disallow value change
        ql.reg.rax = ql.reg.rdi
        ql.verbose = QL_VERBOSE.DEFAULT
        return 0
    @staticmethod
    def apply(ql):
        ql.set_api("tolower", Chal9.tolower_patch)
        pass


class Chal10(BaseChallenge):

    class FakeCmdLine(QlFsMappedObject, ABC):
        def read(self, size):
            print("FakeCmdLine - read")
            return b"qilinglab"

        def fstat(self):
            return -1

        def close(self):
            return 0

    @staticmethod
    def apply(ql):
        ql.add_fs_mapper("/proc/self/cmdline", Chal10.FakeCmdLine())


class Chal11(BaseChallenge):
    """
    Let's try hook on code things
    """
    after_cpuid = False
    @staticmethod
    def cpuid_faking(ql, address, size):

        if Chal11.after_cpuid:
            print("Patched")
            Chal11.after_cpuid = False
            ql.reg.ebx = 0x696C6951
            ql.reg.ecx = 0x614C676E
            ql.reg.edx = 0x20202062

        md = ql.create_disassembler()
        buf = ql.mem.read(address, size)
        for i in md.disasm(buf, address):
            if i.mnemonic == "cpuid":
                print("CPUID!")
                Chal11.after_cpuid = True

    @staticmethod
    def enable_hook_code(ql):
        print("Enable monitoring for CPUID")
        #apply_disasm(ql)
        ql.hook_code(Chal11.cpuid_faking)

    @staticmethod
    def apply(ql):
        ql.hook_address(Chal11.enable_hook_code, ql.base + 0x1581)
        # WHY WE COULD NOT DO THIS?
        # ql.hook_address(Chal11.enable_hook_code, ql.base + 0x1159)
        # WHY SO BIG GAP??
        pass


def apply_disasm(ql):
    ql.verbose = QL_VERBOSE.DISASM


def contest():
    #ql = Qiling([os.path.join("bins", "qilinglab-x86_64")], os.path.join("rootfs", "x8664_linux"))
    # roots from https://github.com/qilingframework/rootfs
    ql = Qiling([os.path.join("bins", "qilinglab-x86_64")], os.path.join("rootfs", "x8664_linux"), verbose=QL_VERBOSE.DEBUG)
    ql.base = 0x0000555555554000
    for chal in BaseChallenge.__subclasses__():
        chal.apply(ql)
    ql.run()
