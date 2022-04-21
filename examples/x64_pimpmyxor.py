#!/usr/bin/env python3

# This example is 'Pimp my xor' from GreHack 2018
# Just as a debug trace example
# Download the file from https://github.com/GreHack/CTF-challs/tree/master/2018/Reverse/100%20-%20pimp_my_xor

from rainbow.generics import rainbow_x64

e = rainbow_x64()
e.load("pimp_my_xor", typ=".elf")

e.mem_trace = 1
e.trace_regs = 1
e.function_calls = 1

# Read the obfuscated password
hidden_string = e[0x404060 : 0x404060 + 0x2E]

# Unscramble it
p = [i ^ j for i, j in zip(b"\x5e" + hidden_string, hidden_string)]

# Set it as input to the function
e[0x404100] = bytes(p)

# Set password length
e["eax"] = 0x2E

# Call function
e.start(0x4010D1, 0x401280)

print("\nFlag is :", e[0x404100 : 0x404100 + 0x2E].decode("utf8"))
