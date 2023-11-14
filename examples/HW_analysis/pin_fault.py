#!/usr/bin/env python3

import numpy as np

from rainbow import HammingWeight, TraceConfig
from rainbow.devices.stm32 import rainbow_stm32f215 as rainbow_stm32
from rainbow.fault_models import fault_skip
from rainbow.utils.plot import viewer

# Pick any reference pin (STORED_PIN) and a different input pin
# Goal is to make 'storage_containsPin' function return a non-null
# value, which would mean the code executes as if the user PIN
# was correct although it was not

STORED_PIN = "1874"
INPUT_PIN = "0000"

def setup_emulator(trace_config=TraceConfig()) -> rainbow_stm32:
    print("Setting up emulator")
    e = rainbow_stm32(trace_config=trace_config)
    e.load("trezor.elf")
    e.setup()

    # as in the side-channel example, this is the location of the reference
    # pin in Flash
    e[0x08008110 + 0x189] = bytes(STORED_PIN + "\x00", "ascii")

    # Pick any address for the input pin...
    e[0xcafecafe] = bytes(INPUT_PIN + "\x00", "ascii")

    return e

def result(u):
    """ Test whether execution was faulted """
    return u['r0'] != 0 and u['pc'] == 0xaaaaaaaa


N = 57

total_faults = 0
total_crashes = 0
fault_trace = [0] * N
crash_trace = [0] * N

e = setup_emulator()
print("Loop on all possible skips")
print("r0 should be 0 at the end of the function if no fault occurred")
for i in range(1, N):
    e.reset()

    # The first fault might not actually work depending
    # on the value of r5 when calling. Remove comment to observe
    # e['r5'] = 0x60000000

    e['r0'] = 0xcafecafe
    e['lr'] = 0xaaaaaaaa

    pc = 0
    try:
        # Run i instruction, then inject skip, then run
        pc = e.start_and_fault(fault_skip, i, e.functions['storage_containsPin'], 0xaaaaaaaa, count=100)
    except RuntimeError:
        # Fault crashed the emulation
        total_crashes += 1
        crash_trace[i] = 1
        d = e.disassemble_single(pc, 4)
        e.print_asmline(pc, d[2], d[3])
        pc += d[1]
        print("crashed")
        continue
    except IndexError:
        pass

    # Print current instruction
    d = e.disassemble_single(pc, 4)
    e.print_asmline(pc, d[2], d[3])
    pc += d[1]

    if result(e):
        # Successful fault
        total_faults += 1
        fault_trace[i] = 1
        print(" <-- r0 =", hex(e['r0']), end="")

print(f"\n=== {total_faults} faults found ===")
print(f"=== {total_crashes} crashes ===")

# get an 'original' side channel trace
e = setup_emulator(trace_config=TraceConfig(register=HammingWeight(), instruction=True))

e['r0'] = 0xcafecafe
e['lr'] = 0xaaaaaaaa

e.start(e.functions['storage_containsPin'], 0xaaaaaaaa)

trace = np.array([event["register"] for event in e.trace if "register" in event], dtype=np.uint8)
fault_trace = trace.max() - np.array(fault_trace, dtype=np.uint8)[:trace.shape[0]] * trace.max()

viewer([event["instruction"] for event in e.trace], np.array([trace, fault_trace]))
