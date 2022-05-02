#!/usr/bin/env python3
# This example retrieves the key from the AES in https://github.com/LedgerHQ/CTF/tree/master/ctf2018/CTF2

from binascii import unhexlify
from random import choice

import lascar
import numpy as np
from lascar.tools.aes import sbox
from visplot import plot

from ripped2 import main_func


class LedgerCtf2Container(lascar.AbstractContainer):

    def generate_trace(self,idx):
        plaintext = "".join(choice("0123456789abcdef") for _ in range(32))
        addresses, leakage = main_func(plaintext)

        return lascar.Trace( np.array([i & 0xFF for i in leakage]), np.frombuffer( unhexlify(plaintext), np.uint8))


N=90
container = LedgerCtf2Container(N)
cpa_engines = [lascar.CpaEngine(f'cpa{i}',lambda plaintext, key_byte, index=i: sbox[plaintext[index]^key_byte], range(256)) for i in range(16)]

s = lascar.Session(container, 
                   engines=cpa_engines,
                   output_method=lascar.ConsoleOutputMethod()).run(1)

# Check the results :
print("Key should be : f0 33 1c e0 26 6a da ce 86 a8 a1 3b fa 14 67 40")

K = list(
    map(lambda x: int(x, 16), "f0 33 1c e0 26 6a da ce 86 a8 a1 3b fa 14 67 40".split())
)

for i, engine in enumerate(cpa_engines):
    print(
        hex(K[i]),
        (K[i] == np.abs(engine.finalize()).max(1).argmax())
        and "found !"
        or "not found",
    )

# Let's draw one result
v = plot(cpa_engines[3].finalize(), dontrun=True)
v.multiple_select(K[3])
v.run()
