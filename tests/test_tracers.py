import pytest
import unicorn as uc
from rainbow.generics import rainbow_arm
from rainbow.tracers import regs_hw_sum_trace, regs_hd_sum_trace, wb_regs_trace

all_regs_tracers = [regs_hw_sum_trace, regs_hd_sum_trace, wb_regs_trace]


@pytest.mark.parametrize("regs_tracer", all_regs_tracers)
def test_regs_tracer(regs_tracer):
    emu = rainbow_arm(sca_mode=True)
    emu.load("examples/CortexM_AES/aes.bin", typ=".elf")
    emu.trace_regs = True

    # Setup tracer
    emu.emu.hook_del(emu.ct_hook)
    emu.ct_hook = emu.emu.hook_add(uc.UC_HOOK_CODE, regs_tracer, emu)

    # Setup data
    key = bytes(range(16))
    key_addr = 0xDEAD0000
    emu[key_addr] = key
    rk_addr = 0xDEAD1000
    emu[rk_addr] = key

    # AES_128_keyschedule(key, rk+16)
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.trace_reset()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.sca_values_trace) > 0


@pytest.mark.parametrize("regs_tracer", all_regs_tracers)
def test_regs_tracer_discard(regs_tracer):
    emu = rainbow_arm(sca_mode=True)
    emu.load("examples/CortexM_AES/aes.bin", typ=".elf")
    emu.trace_regs = True

    # Setup tracer
    emu.emu.hook_del(emu.ct_hook)
    emu.ct_hook = emu.emu.hook_add(uc.UC_HOOK_CODE, regs_tracer, emu)

    # Setup data
    key = bytes(range(16))
    key_addr = 0xDEAD0000
    emu[key_addr] = key
    rk_addr = 0xDEAD1000
    emu[rk_addr] = key

    # AES_128_keyschedule(key, rk+16)
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.trace_reset()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.sca_values_trace) > 0
    trace1 = emu.sca_values_trace

    # Again but without r0-r4
    emu.TRACE_DISCARD = ["r0", "r1", "r2", "r3", "r4"]
    emu["r0"] = key_addr
    emu["r1"] = rk_addr + 16
    emu.trace_reset()
    emu.start(emu.functions["AES_128_keyschedule"] | 1, 0)
    assert len(emu.sca_values_trace) > 0
    trace2 = emu.sca_values_trace
    assert trace1 != trace2
