from rainbow.generics import rainbow_x64
from binascii import unhexlify

# change this value to switch between normal 
# execution, and side-channel analysis version
SCA_EXEC = False 

e = rainbow_x64(sca_mode=SCA_EXEC)
e.load("ctf2", typ=".elf")

input_buf = 0xCAFE1000
e[input_buf] = b"00112233445566778899aabbccddeeff"

argv = 0xCAFE0000
e[argv + 8] = input_buf

e["rdi"] = 2  # argc
e["rsi"] = argv

def bypass(emu):
  return True

from random import getrandbits

if SCA_EXEC:
  def pyrand(emu, val):
    emu['rax'] = val
    return True
else:
  def pyrand(emu, val):
    emu['rax'] = getrandbits(8)
    return True

def pystrtol(emu):
  ad = emu['rdi']
  emu['rax'] = int(emu[ad:ad+2], 16)
  return True

def pyputs(emu):
  src = emu['rdi']
  i = 0
  c = emu[src]
  while c != b'\x00':
    print(chr(c[0]), end='' )
    i += 1
    c = emu[src+i]
  return True

e.stubbed_functions['time'] = bypass 
e.stubbed_functions['srand'] = bypass 
e.stubbed_functions['strtol'] = pystrtol 
e.stubbed_functions['clock_gettime'] = bypass 
e.stubbed_functions['puts'] = pyputs

if SCA_EXEC:
  e.trace_regs = 1
  e.mem_trace = 1
else:
  e.trace = 0
# e.function_calls = True

e.stubbed_functions['rand'] = lambda emu: pyrand(emu,0) 
e.start(e.functions['main'], 0x103c)
print('first part done')
e.stubbed_functions['rand'] = lambda emu: pyrand(emu,7) 

if SCA_EXEC:
  e.start(0x10ba, 0x1151, count=5000)
else:
  e.start(0x10ba, 0x1409)
print('\nDone')

from binascii import hexlify

ofs = 0xd03660
for i in range(0, 16*15,16):
  print(hexlify(e[ofs+i:ofs+i+16]))

if e.sca_mode:
  import numpy as np
  from rainbow.utils import plot, hw

  print(len(e.sca_values_trace))

  trace = (np.array(e.sca_values_trace) & 0xffffffff).astype(np.uint32)
  plot(trace)