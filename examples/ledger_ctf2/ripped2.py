#!/usr/bin/env python3
# This file contains the ripped_out parts of the binary
# that we'd like to emulate and trace

from rainbow.generics import rainbow_x64
from binascii import unhexlify

# Some external function calls need to be stubbed
# We just force them to return 0
def time(em):
    em["rax"] = 0

def clock_gettime(em):
    em["rax"] = 0

def rand(em):
    em["rax"] = 7


e = rainbow_x64(sca_mode=True)
e.load("ctf2", typ=".elf")
e.mem_trace = 1

e.hook_bypass("time", time)
e.hook_bypass("srand")
e.hook_bypass("clock_gettime", clock_gettime)
e.hook_bypass("rand", rand)

def main_func(inputt):
    e[0xd037a0:0xd037a0+16] = 0

    # Resets the leakage trace
    e.reset()
    e.reset_trace()

    inp = iter(unhexlify(inputt))

    def strtol(em):
        em["rax"] = next(inp)

    e.hook_bypass("strtol", strtol)

    e.start(0xca9, 0x1038)
    print('', end='') # Here to avoid some obscure race condition in unicorn
    e.start(0x10BA, 0x13DA, count=5000)

    return e.sca_address_trace, e.sca_values_trace


if __name__ == "__main__":
    addr, trace = main_func("00112233445566778899aabbccddeeff")

    from visplot import plot
    plot(trace)
