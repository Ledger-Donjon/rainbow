# This file contains the ripped_out parts of the binary
# that we'd like to emulate and trace

from rainbow.generics import rainbow_x64
from binascii import unhexlify

# Some external function calls need to be stubbed
# We just force them to return 0
def time(em):
    em["rax"] = 0
    return True

def srand(em):
    return True

def clock_gettime(em):
    em["rax"] = 0
    return True

def rand(em):
    em["rax"] = 7
    return True


e = rainbow_x64(sca_mode=True, local_vars=globals())
e.load("ctf2", typ=".elf")
e.mem_trace = 1

def main_func(inputt):
    e[0xd037a0:0xd037a0+16] = 0

    # Resets the leakage trace
    e.reset()
    e.trace_reset()

    inp = iter(unhexlify(inputt))

    def strtol(em):
        em["rax"] = next(inp)
        return True

    e.stubbed_functions["strtol"] = strtol

    e.start(0xca9, 0x1038)
    print('', end='') # Here to avoid some obscure race condition in unicorn
    e.start(0x10BA, 0x13DA, count=5000)

    return e.sca_address_trace, e.sca_values_trace


if __name__ == "__main__":
    addr, trace = main_func("00112233445566778899aabbccddeeff")

    from rainbow.utils import plot
    plot(trace)

