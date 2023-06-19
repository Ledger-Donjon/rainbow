#!/usr/bin/env python3

# UINT aes(UCHAR Mode, STRUCT_AES* struct_aes, const UCHARp key, const UCHARp input, UCHARp output, const UCHARp random_aes, const UCHARp random_key)
# aes( 0xb, ...)

from random import randbytes

import numpy as np
from visplot import plot
from binascii import hexlify
from rainbow import TraceConfig, HammingWeight, Print
from Crypto.Cipher import AES
from rainbow.generics import rainbow_arm


def f_aes(e, key, input_):
    e.reset()

    # mode : 0xb = MODE_ENC | MODE_AESINIT_ENC | MODE_KEYINIT
    e['r0'] = 0xb

    # struct_aes
    struct_aes_p = 0xcafe0000
    e[struct_aes_p] = 0
    # struct is huge so we need to map another page
    e[struct_aes_p + e.PAGE_SIZE] = 0
    e['r1'] = struct_aes_p

    # key
    key_p = 0xcafe1000
    e[key_p] = key
    e['r2'] = key_p

    # input
    input_p = 0xcafe2000
    e[input_p] = input_
    e['r3'] = input_p

    # output 
    output_p = 0xdead0000
    e[output_p] = 0
    # ARM calling convention : 4th+ parameter is on stack
    e[e['sp']] = output_p

    # rest stays to 0
    e.start(e.functions['aes'] | 1, 0)

    if e['r0']:
        print('ERROR !')

    res = e[output_p:output_p + 16]
    aes_c = AES.new(key, AES.MODE_ECB)
    ref = aes_c.encrypt(input_)
    if ref != res:
        print("Nope :")
        print(hexlify(res))
        print(hexlify(ref))
    return res


if __name__ == "__main__":
    e = rainbow_arm(print_config=Print.Code | Print.Functions, trace_config=TraceConfig(register=HammingWeight()))
    e.load('firmware.elf')
    e.setup()

    return_addr = 0
    # map it to prevent an unmapped fetch exception
    e[return_addr] = 0

    key = b"\x7a" * 16
    traces = []
    for i in range(5):
        print(".", end='')

        f_aes(e, key, randbytes(16))
        traces.append(np.fromiter(map(lambda event: event["register"], e.trace), dtype=np.float32))

    traces = np.array(traces)
    traces += np.random.normal(0, 1, size=traces.shape)

    v = plot(traces, dontrun=True)
    v.multiple_select(0)
    v.run()
