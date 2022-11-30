import pytest
from rainbow.generics import rainbow_x64


def test_hook_bypass_ctf2_name():
    emu = rainbow_x64()
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")

    def strtol(e):
        e["rax"] = 0

    emu.hook_bypass("strtol", strtol)
    emu.start(0xCA9, 0xDCE)


def test_hook_bypass_ctf2_addr():
    emu = rainbow_x64()
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")

    def strtol(e):
        e["rax"] = 0

    emu.hook_bypass(2109344, strtol)
    emu.start(0xCA9, 0xDCE)


def test_hook_bypass_ctf2_name_empty():
    emu = rainbow_x64()
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    emu.hook_bypass("strtol")
    emu.start(0xCA9, 0xDCE)


def test_hook_bypass_missing_name():
    emu = rainbow_x64()
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")
    with pytest.raises(IndexError):
        emu.hook_bypass("strtol_blabla")


def test_hook_prolog_missing_name():
    emu = rainbow_x64()
    emu.load("examples/ledger_ctf2/ctf2", typ=".elf")

    def strtol(e):
        pass

    with pytest.raises(IndexError):
        emu.hook_prolog("strtol_blabla", strtol)


def test_remove_hooks():
    emu = rainbow_x64()
    emu.remove_hooks()
