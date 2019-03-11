# aes128 from https://github.com/Ko-/aes-armcortexm

import numpy as np
from rainbow.generics import rainbow_arm
from rainbow.utils import hw


def aes_encrypt(key, plaintext):
    e = rainbow_arm(sca_mode=True)
    e.load("aes.bin", typ=".elf")

    e.mem_trace = True
    e.trace_regs = True

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

    ## Read out the ciphertext
    # ciphertext = e[buf_out:buf_out+16]

    # Hamming weight + noise to pretend we're on a real target
    trace = np.array([hw(i) for i in e.sca_values_trace]) + np.random.normal(
        0, 1.0, (len(e.sca_values_trace))
    )
    return trace


if __name__ == "__main__":
    from random import getrandbits as rnd

    KEY = bytes(range(16))

    N = 100
    values = np.array([[rnd(8) for j in range(16)] for k in range(N)], dtype=np.uint8)
    traces = np.array([aes_encrypt(KEY, bytes(values[i])) for i in range(N)])

    from rainbow.utils import plot

    plot(traces[:5])

    from lascar.container import TraceBatchContainer
    from lascar import Session, CpaEngine, ConsoleOutputMethod
    from lascar.tools.aes import sbox

    t = TraceBatchContainer(traces, values)

    s = Session(t, output_method=ConsoleOutputMethod())
    s.add_engines(
        [
            CpaEngine(f"cpa{i}", lambda v, k, z=i: sbox[v[z] ^ k], range(256))
            for i in range(16)
        ]
    )

    s.run()

    print(s.output_method.finalize())

    plot(s['cpa1'].finalize(), highlight=KEY[1])
