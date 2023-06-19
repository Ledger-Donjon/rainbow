#!/usr/bin/env python3
# aes128 from https://github.com/Ko-/aes-armcortexm

from binascii import hexlify

import lascar
import numpy as np
from lascar.tools.aes import sbox
from rainbow.generics import rainbow_arm
from rainbow import TraceConfig, HammingWeight
from visplot import plot

e = rainbow_arm(trace_config=TraceConfig(register=HammingWeight()))
e.load("aes.bin", typ=".elf")
e.setup()


def aes_encrypt(key, plaintext):
    e.reset()
    key_addr = 0xDEAD0000
    e[key_addr] = key
    rk_addr = 0xDEAD1000
    e[rk_addr] = key

    # AES_128_keyschedule(key, rk+16)
    e["r0"] = key_addr
    e["r1"] = rk_addr + 16
    e.start(e.functions["AES_128_keyschedule"] | 1, 0)

    buf_in = 0xDEAD2000
    buf_out = 0xDEAD3000
    e[buf_in] = plaintext
    e[buf_out] = b"\x00" * 16  # Need to do this so this buffer is mapped into unicorn

    # AES_128_encrypt(rk, buf_in, buf_out)
    e["r0"] = rk_addr
    e["r1"] = buf_in
    e["r2"] = buf_out
    # e.trace_reset()
    e.start(e.functions["AES_128_encrypt"] | 1, 0)

    # Hamming weight + noise to pretend we're on a real target
    trace = np.array([event["register"] for event in e.trace]) + np.random.normal(
        0, 1.0, (len(e.trace))
    )
    return trace


class CortexMAesContainer(lascar.AbstractContainer):

    def generate_trace(self, idx):
        plaintext = np.random.randint(0, 256, (16,), np.uint8)
        leakage = aes_encrypt(KEY, plaintext.tobytes())
        return lascar.Trace(leakage, plaintext)


N = 100
KEY = bytes(range(16))

container = CortexMAesContainer(N)

cpa_engines = [
    lascar.CpaEngine(lambda plaintext, key_byte, index=i: sbox[plaintext[index] ^ key_byte], range(256)) for
    i in range(16)]
s = lascar.Session(CortexMAesContainer(N), engines=cpa_engines, name="lascar CPA").run()

key = bytes([engine.finalize().max(1).argmax() for engine in cpa_engines])
print("Key is :", hexlify(key).upper())

# Let's draw one result
v = plot(cpa_engines[1].finalize(), dontrun=True)
v.multiple_select(KEY[1])
v.run()
