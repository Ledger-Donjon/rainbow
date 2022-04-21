#!/usr/bin/env python3
# This file contains the ripped_out parts of the binary
# that we'd like to emulate and trace

from rainbow.generics import rainbow_x64
from binascii import unhexlify

# Some external function calls need to be stubbed
# We just force them to return 0
def time(em):
    em["eax"] = 0
    return True


def clock_gettime(em):
    em["eax"] = 0
    return True


def srand(em):
    em["eax"] = 0
    return True


# Set up a x64 emulator in side-channel mode (no text output) and
# pass the previous functions to the redefined functions dictionary
e = rainbow_x64(sca_mode=True)
e.stubbed_functions = {
    "time": time,
    "clock_gettime": clock_gettime,
    "srand": srand,
}

# load the elf
e.load("ctf2", typ=".elf")

# We'd like to trace everything we can
# - memory accesses
# - modified registers
e.mem_trace = 1
e.trace_regs = 1


def main_func(inputt):
    e.reset()

    # Setup call parameters.
    # Let's declare 'argv' is at 0x200000
    # and that our input is in 0x300000
    argv = 0xCAFE0000
    input_buf = 0xCAFE1000

    # argv[1] (pointer to our input buffer)
    e[argv + 8] = input_buf
    e[input_buf] = bytes(inputt, "utf8")

    # Now some parameters on the stack
    # e[e.STACK_ADDR+16] = 0xdeaddead  # return. ignored because we don't reach execution end
    e[e.STACK_ADDR + 8] = input_buf
    e[e.STACK_ADDR + 0] = 0

    e["rdi"] = 2  # argc
    e["rsi"] = argv

    inp = iter(unhexlify(inputt))

    # To transmit the input to the execution
    # one way among others, we can hook the call
    # to 'strtol' to dispatch one byte at a time
    def strtol(em):
        em["eax"] = next(inp)

    # Tell the emulator that we redefined this function
    e.hook_bypass("strtol", strtol)

    # In order to attack this binary efficiently,
    # we need the 'rand' function to output 0 in the first
    # part of the emulation to disable the random masking,
    # and to output '7' during scheduling to force the
    # execution of the 'correct' AES among the dummy ones
    # randval = 0

    def rand(em):
        # em["rax"] = randval
        em["rax"] = 0

    e.hook_bypass("rand", rand)

    # First part : retrieves the input and resets the scheduling
    ret = e.start(e.functions["main"], 0x1038)

    # sometimes execution stops if this line is not there (unicorn instance gets gc'ed ?)
    print(ret * " ", end="")

    # Now switch 'rand' to 7 so that we'll execute the correct AES's
    # first round
    # randval = 7
    def rand(em):
        em["rax"] = 7 
        return True

    # This needs to be done again to point to the new function
    e.hook_bypass("rand", rand)

    # Here we start at 0x10ba so that we skip the binary's self crc-checking
    # although it would work because we did not modify the binary, we would
    # need to reimplement the streambuf function.
    # Also we don't need to execute a lot of instructions to get the leakage
    # so let's set a limit to 5000
    e.start(0x10BA, 0x13DA, count=5000)

    return e.sca_address_trace, e.sca_values_trace


if __name__ == "__main__":
    addr, trace = main_func("aa" * 16)
