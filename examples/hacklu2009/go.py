# Hack.lu ctf 2009
from rainbow.generics import rainbow_x86
from binascii import unhexlify, hexlify

e = rainbow_x86(sca_mode=True)
e.load('crackme.exe')

def encrypt(plain):
    # Reset the emulator state
    e.trace_reset()
    for r in e.INTERNAL_REGS:
        e[r] = 0
    e['esp'] = e.STACK_ADDR
    e['ebp'] = e.STACK_ADDR

    # Load the plaintext into memory
    # the state is loaded column-wise
    order = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    for i,j in enumerate(order):
        e[0xdeadbe00+i] = plain[j]

    # the encryption function is identified at 0x401050
    # it takes its input parameter from stack+4
    e[e.STACK_ADDR+4] = 0xdeadbe00
    e.start(0x401050, 0, count=1000)

    return e.sca_values_trace


if __name__ == "__main__":
    from random import getrandbits
    import numpy as np

    N = 20

    plains = []
    traces = []
    for i in range(N):
        print(i, end=' ')
        plains.append(bytes([getrandbits(8) for _ in range(16)]))
        traces.append(encrypt(plains[-1]))

    print('Done\n')

    plainst = np.array([np.array(list(pl)) for pl in plains], dtype=np.uint8)
    npt = np.array(traces, dtype=np.uint32) & 0xff

    from lascar import *
    from lascar.tools.aes import sbox

    s = Session(TraceBatchContainer(npt, plainst))
    s.add_engines([CpaEngine(f'cpa{i}', lambda p,k,z=i:sbox[p[z]^k], range(256)) for i in range(16)])
    s.run()

    key = bytes([s[f'cpa{i}'].finalize().max(1).argmax() for i in range(16)])

    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_ECB)
    print("Serial is :", hexlify(cipher.decrypt(bytes("hack.lu-2009-ctf", 'utf8'))).upper())