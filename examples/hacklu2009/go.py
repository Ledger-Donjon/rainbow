#!/usr/bin/env python3
# Hack.lu ctf 2009

from binascii import hexlify

import lascar
import numpy as np
from lascar.tools.aes import sbox
from rainbow.generics import rainbow_x86

e = rainbow_x86(sca_mode=True)
e.load('crackme.exe')


def encrypt(plain):
    # Reset the emulator state
    e.reset()

    # Load the plaintext into memory
    # the state is loaded column-wise
    order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    for i, j in enumerate(order):
        e[0xdeadbe00 + i] = plain[j]

    # the encryption function is identified at 0x401050
    # it takes its input parameter from stack+4
    e[e.STACK_ADDR + 4] = 0xdeadbe00
    e.start(0x401050, 0, count=1000)

    return e.sca_values_trace


class CrackMeContainer(lascar.AbstractContainer):

    def generate_trace(self, idx):
        plaintext = np.random.randint(0, 256, (16,), np.uint8)
        leakage = np.array(encrypt(plaintext.tobytes())) & 0xff
        return lascar.Trace(leakage, plaintext)


N = 20
cpa_engines = [
    lascar.CpaEngine(f'cpa{i}', lambda plaintext, key_byte, index=i: sbox[plaintext[index] ^ key_byte], range(256)) for
    i in range(16)]

s = lascar.Session(CrackMeContainer(N), engines=cpa_engines, name="lascar CPA").run()
key = bytes([engine.finalize().max(1).argmax() for engine in cpa_engines])

from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_ECB)
print("Serial is :", hexlify(cipher.decrypt(bytes("hack.lu-2009-ctf", 'utf8'))).upper())
