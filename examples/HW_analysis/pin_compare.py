#!/usr/bin/env python3
import random
from rainbow.devices.stm32 import rainbow_stm32f215 as rainbow_stm32
from rainbow import TraceConfig, HammingWeight
import numpy as np
from lascar import TraceBatchContainer, Session, NicvEngine
from rainbow.utils.plot import viewer


def containsPin(e, pin_attempt, stored_pin):
    """ Handle calling the pin comparison function using the emulator """
    e.reset()

    stor_pin = 0x08008110 + 0x189  # address of the storagePin->rom
    e[stor_pin] = bytes(stored_pin + "\x00", "ascii")

    input_pin_addr = 0xcafecafe
    e[input_pin_addr] = bytes(pin_attempt + "\x00", "ascii")

    e['r0'] = input_pin_addr
    e['lr'] = 0xaaaaaaaa

    e.start(e.functions['storage_containsPin'], 0xaaaaaaaa)


def show_nicv(values, traces, nr_digits):
    """ Compute the Normalized Inter-Class Variance as in the article """
    values = np.array(values, dtype=np.uint8)
    traces = np.array(traces)

    # Use the Hamming weight of leaked values and add some noise
    # through the 'leakage_processing' parameter
    t = TraceBatchContainer(
        traces,
        values,
    )

    s = Session(t)

    # Input value leakage
    # s.add_engines([NicvEngine('a'+str(i), lambda v,z=i:v[z], range(9)) for i in range(nr_digits)])

    # Difference leakage
    s.add_engines(
        [NicvEngine('a' + str(i), lambda v, z=i: 9 + np.int8(v[z]) - np.int8(ord(STORED_PIN[z])), range(17)) for i in
         range(nr_digits)])

    # below is a variant on the carry bit
    # s.add_engines([NicvEngine('c'+str(i), lambda v,z=i:int(v[z]>ord(STORED_PIN[z])), range(2)) for i in range(nr_digits)])

    s.run()

    return np.array([s[eng]._finalize() for eng in s.engines if eng not in ['mean', 'var']])


if __name__ == "__main__":
    STORED_PIN = "1874"
    N = 500

    print("Setting up emulator")
    e = rainbow_stm32(trace_config=TraceConfig(register=HammingWeight(), instruction=True))
    e.load("trezor.elf")
    e.setup()

    print("Generating", N, "traces")

    values = []
    traces = []
    for i in range(N):
        input_pin = "".join(random.choice("123456789") for _ in range(len(STORED_PIN)))
        containsPin(e, input_pin, STORED_PIN)
        values.append(np.array([ord(x) for x in input_pin + STORED_PIN], dtype=np.uint8))
        traces.append(np.array([event["register"] for event in e.trace if "register" in event]))

    print("Using Lascar to get an NICV")

    res = show_nicv(values, traces, nr_digits=len(STORED_PIN))

    viewer([event["instruction"] for event in e.trace], res)
