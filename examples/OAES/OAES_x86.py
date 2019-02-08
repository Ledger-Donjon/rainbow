from rainbow.generics import rainbow_x86, rainbow_arm
import numpy as np
from binascii import unhexlify, hexlify


def generate_targetf():
    e = rainbow_x86(sca_mode=True)

    e.load("libnative-lib_x86.so")
    target_func = "_Z48TfcqPqf1lNhu0DC2qGsAAeML0SEmOBYX4jpYUnyT8qYWIlEqPhS_"

    e.trace = 1
    e.mem_trace = 1
    e.trace_regs = 1

    def targetf(inp, length):
        e.trace_reset()
        e[e.STACK[0] : e.STACK[1]] = 0

        for r in e.INTERNAL_REGS:
            e[r] = 0

        e["EBP"] = e.STACK_ADDR
        e["ESP"] = e.STACK_ADDR

        e[0xBADC0FE0] = unhexlify(inp)
        e[0xA5A5A5A5] = unhexlify(inp)
        # e[e.STACK_ADDR] = 0xDEADBEEF
        e[e.STACK_ADDR + 4] = 0xBADC0FE0
        e[e.STACK_ADDR + 8] = 0xA5A5A5A5
        e.start(e.functions[target_func], 0, count=length)

        return e.sca_address_trace, e.sca_values_trace

    return e, targetf


def get_traces(targetf, nb, nb_samples):
    import random

    values = []
    traces = []
    for i in range(nb):
        inp = "".join(random.choice("0123456789abcdef") for _ in range(32))
        address_trace, values_trace = targetf(inp, nb_samples)
        values.append([i for i in bytes(inp, "utf8")])
        traces.append(values_trace)
        print(".", end="")

    addresses = address_trace

    values = np.array(values, dtype=np.uint8)

    lgst_dim = max(map(len, traces))

    # we're gonna split each 32bit value in 8 bit chunks
    lgst_dim *= 4

    tmp = np.zeros((len(traces), lgst_dim), dtype=np.float32)
    for i, t in enumerate(traces):
        for x in range(len(t)):
            for j in range(4):
                tmp[i][x * 4 + j] = (t[x] >> (8 * j)) & 0xFF

    return values, tmp, addresses


if __name__ == "__main__":
    _, func = generate_targetf()
    values, traces, addresses = get_traces(func, 10, 1000000)

    from lascar import TraceBatchContainer, Session

    t = TraceBatchContainer(traces, values)
    s = Session(t)
    s.run()

    from rainbow.utils.plot import viewer

    viewer(addresses, s.engines["var"].finalize())
