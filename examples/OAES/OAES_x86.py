#!/usr/bin/env python3

from binascii import unhexlify
import random
import numpy as np
from rainbow.generics import rainbow_x86
from rainbow import TraceConfig, HammingWeight, Identity
from lascar import Session, TraceBatchContainer


def generate_targetf():
    e = rainbow_x86(trace_config=TraceConfig(register=HammingWeight(), mem_value=Identity()))
    e.load("libnative-lib_x86.so")
    e.setup()

    target_func = "_Z48TfcqPqf1lNhu0DC2qGsAAeML0SEmOBYX4jpYUnyT8qYWIlEqPhS_"

    def targetf(inp, length):
        e.reset()
        e[e.STACK[0] : e.STACK[1]] = 0

        e[0xBADC0FE0] = unhexlify(inp)
        e[0xA5A5A5A5] = unhexlify(inp)
        # e[e.STACK_ADDR] = 0xDEADBEEF
        e[e.STACK_ADDR + 4] = 0xBADC0FE0
        e[e.STACK_ADDR + 8] = 0xA5A5A5A5
        e.start(e.functions[target_func], 0, count=length)

        return [event["register"] if event["type"] == "reg" else event["mem_value"] for event in e.trace]

    return e, targetf


def get_traces(targetf, nb, nb_samples):
    values = []
    traces = []
    for i in range(nb):
        inp = "".join(random.choice("0123456789abcdef") for _ in range(32))
        values_trace = targetf(inp, nb_samples)
        values.append([i for i in bytes(inp, "utf8")])
        traces.append(values_trace)
        print(".", end="")

    values = np.array(values, dtype=np.uint8)

    lgst_dim = max(map(len, traces))

    # we're gonna split each 32bit value in 8 bit chunks
    lgst_dim *= 4

    tmp = np.zeros((len(traces), lgst_dim), dtype=np.float32)
    for i, t in enumerate(traces):
        for x in range(len(t)):
            for j in range(4):
                tmp[i][x * 4 + j] = (t[x] >> (8 * j)) & 0xFF

    return values, tmp


if __name__ == "__main__":
    _, func = generate_targetf()
    values, traces = get_traces(func, 10, 1000000)

    t = TraceBatchContainer(traces, values)
    s = Session(t)
    s.run()
