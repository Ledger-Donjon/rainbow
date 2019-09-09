# This example retrieves the key from the AES in https://github.com/LedgerHQ/CTF/tree/master/ctf2018/CTF2

from binascii import unhexlify
from ripped2 import main_func
from random import choice

import numpy as np

# Main loop : choose random inputs, store them in 'plains'
# call function with said input and retrieve execution trace
traces = []
plains = []
for i in range(80):
    print("-" * 8, i)

    plain = "".join(choice("0123456789abcdef") for _ in range(32))
    addresses, trace = main_func(plain)

    plains.append(list(unhexlify(plain)))
    traces.append([i & 0xFF for i in trace])


# Some numpy conversion required
values = np.array(plains, dtype=np.uint8)

lgst_dim = max(map(len, traces))
tmp = np.zeros((len(traces), lgst_dim), dtype=np.float32)
for i, t in enumerate(traces):
    # pad to longest trace (even though they might well be all the same length)
    tmp[i][: len(t)] = np.array(t, dtype=np.float32)
traces = tmp


## Phase 2 : attack with Lascar
## Launch 16 CPAs on the outputs of the sbox

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

# print(s.output_method.finalize())

# Check the results :
print("Key should be : f0 33 1c e0 26 6a da ce 86 a8 a1 3b fa 14 67 40")

K = list(
    map(lambda x: int(x, 16), "f0 33 1c e0 26 6a da ce 86 a8 a1 3b fa 14 67 40".split())
)

for i, n in enumerate([f"cpa{i}" for i in range(16)]):
    print(
        hex(K[i]),
        (K[i] == np.abs(s[n]._finalize()).max(1).argmax())
        and "found !"
        or "not found",
    )

# Let's draw one result
v = s["cpa3"]._finalize()

from rainbow.utils import plot

plot(v, highlight=0xE0)
