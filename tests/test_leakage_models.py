import pytest
from rainbow.generics import rainbow_arm
from rainbow.leakage_models import HammingWeight, HammingDistance, Identity
from rainbow.rainbow import TraceConfig

all_models = [Identity, HammingWeight, HammingDistance]
all_options = ["register", "mem_address", "mem_value"]


@pytest.mark.parametrize("leakage_model", all_models)
@pytest.mark.parametrize("option", all_options)
def test_regs_tracer(leakage_model, option):
    tr = TraceConfig()
    setattr(tr, option, leakage_model())
    emu = rainbow_arm(trace_config=tr)
    emu.load("examples/CortexM_AES/aes.bin", typ=".elf")
    emu.setup()

    # Setup data
    key = bytes(range(16))
    key_addr = 0xDEAD0000
    emu[key_addr] = key
    rk_addr = 0xDEAD1000
    emu[rk_addr] = key

    # AES_128_keyschedule(key, rk+16)
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.reset_trace()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.trace) > 0


@pytest.mark.parametrize("leakage_model", all_models)
def test_regs_tracer_discard(leakage_model):
    emu = rainbow_arm(trace_config=TraceConfig(register=leakage_model()))
    emu.load("examples/CortexM_AES/aes.bin", typ=".elf")
    emu.setup()

    # Setup data
    key = bytes(range(16))
    key_addr = 0xDEAD0000
    emu[key_addr] = key
    rk_addr = 0xDEAD1000
    emu[rk_addr] = key

    # AES_128_keyschedule(key, rk+16)
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.reset_trace()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.trace) > 0
    trace1 = emu.trace

    # Again but without r0-r4
    emu.trace_config.ignored_registers = {"r0", "r1", "r2", "r3", "r4"}
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.reset_trace()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.trace) > 0
    trace2 = emu.trace
    assert trace1 != trace2
