[![Join the chat at https://gitter.im/Ledger-Donjon/rainbow](https://badges.gitter.im/Ledger-Donjon/rainbow.svg)](https://gitter.im/Ledger-Donjon/rainbow?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

# Rainbow

It makes unicorn traces.

Using [Unicorn](http://www.unicorn-engine.org/) as a basis, Rainbow aims to provide an easy scripting interface to loosely emulate embedded binaries, trace them to perform side-channels, and simulate fault injections.

This is to allow quick and easy testing of physical attack resistance of code snippets, in order to help developers have a first evaluation of the resistance of their code.

An introduction is available [here](https://medium.com/ledger-on-security-and-blockchain/introducing-rainbow-donjons-side-channel-analysis-simulation-tool-2f23fa1f11b3).

A blogpost demonstrating how to turn this tool into an automatic fault injection test pipeline is [here](https://blog.ledger.com/fault-injection-simulation/), with the corresponding Rust code [here](https://github.com/Ledger-Donjon/fault_injection_checks_demo/).

## Installation

You will need Python 3.7 at least.

- `pip install .`

If Unicorn or Capstone fails to install somehow:
- Unicorn: http://www.unicorn-engine.org/download/
- Capstone: https://www.capstone-engine.org/

For the side-channel examples, you need to the latest [Lascar](https://github.com/Ledger-Donjon/lascar),
the following command installs the necessary packages.

- `pip install .[examples]`

If you wish to use another version of Python, you can drop an issue and we will look into it.

## Running the examples

Some examples will use Lascar's side-channel attacks and try to display traces using a custom plotter ([visplot](https://github.com/Ledger-Donjon/visplot)) built on top of [Vispy](https://github.com/vispy/vispy). If you want to run those, you will need Vispy and `pyqt5` for the instruction trace + execution trace viewer.

In the `./examples/` folder, you will find:
- [x64_pimpmyxor.py](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/pimp_my_xor/x64_pimpmyxor.py): basic emulation of [this challenge](https://github.com/GreHack/CTF-challs/tree/master/2018/Reverse/100%20-%20pimp_my_xor)
- [CortexM_AES](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/CortexM_AES/cortexm_aes.py): a simple ARM Thumb AES
- [Hacklu2009](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/hacklu2009/go.py): a side-channel solution of a whitebox challenge
- HW_analysis: a side-channel simulation of a [pin comparison](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/HW_analysis/pin_compare.py), and a [fault injection](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/HW_analysis/pin_fault.py) simulation
- [ledger_ctf2](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/ledger_ctf2/ledger_ctf2.py): side-channel solution of a whitebox challenge
- [OAES](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/OAES/OAES_x86.py): an x86 whitebox tracing example that discards useless instructions
- [SecAESSTM32](https://github.com/Ledger-Donjon/rainbow/blob/master/examples/SecAESSTM32/go.py): a starting point to test ANSSI's STM32 [secure AES implementation](https://github.com/ANSSI-FR/SecAESSTM32)

## Example output

See the `x64_pimp_my_xor` example for a debug trace.

In the comment part of each line (after the semicolon), the memory access that was performed is written in a simplified way: `[address] <- value` for a load or `value -> [address]` for a store. Right after, if any register was modified during this instruction, its new value is shown.

At a branch instruction, if the destination is a known function, its name is shown together with the return address and the function's address.

## Basic usage

Grab a device or generic emulator like so:

```python
from rainbow.devices import rainbow_stm32f215

e = rainbow_stm32f215()
```

Load a binary:

```python
e.load('file', typ='.elf')
e.setup()
```

File type is guessed on the extension when possible (.elf, .hex).

Starting the emulation is done like so:

```python
e.start(start_address, stop_address, count=number_of_instructions)
```

Just like with unicorn. The underlying Unicorn instance is always available as `e.emu`.

To enable printing as code gets executed, simply use the `Print` flag.

```python
from rainbow import Print
import colorama

colorama.init()  # Only do this once to enable colors

e = rainbow_stm32f215(print=Print.Code | Print.Functions)  # see other values of the flag
```

## Side-Channel simulation

Rainbow only produces an execution trace, without applying any processing (such as adding noise) on the values.
This is left as some post-processing, so that the user can apply its own leakage model and simulate various conditions from the same traces.
Also, not introducing any noise allows testing in a worst-case scenario, which can yield important results.

To perform the analysis, one can use [Lascar](https://github.com/Ledger-Donjon/lascar).
You can find some scripts in the `examples` folder here which already use it.

To setup tracing (to produce an execution trace) use the `trace_config` option
to the emulator. The following piece of code sets up tracing of register
using the Hamming weight leakage model.
```python
from rainbow import TraceConfig, HammingWeight

e = rainbow_stm32f215(trace_config=TraceConfig(register=HammingWeight()))
e.load('file', typ='.elf')
e.setup()

e.start(start_address)

print(e.trace)
# [{"type": "code", "register": 7}, {"type": "code": "register": 5}]
```

If you setup tracing for `mem_address`, then the `e.trace` list will have dictionaries
like `{"type": "mem_read", "address": 1234}` or `{"type": "mem_write", "address": 1234}`
with the value of the `address` entry passed through the leakage model. Tracing for 
`mem_value` does the same, but traces memory values read or written and produces entries
like  `{"type": "mem_read", "value": 1234}`. Note that these approaches can be combined,
resulting in the dictionary having both an `address` and `value` entries.

If you setup tracing for `code`, dissasembled instructions will be available in the
trace with dictionaries like `{"type": "code", "instruction": "     404 ldm.w   r0, {r4, r5, r6, r7}"}`.
Note that this tracing option combined with register tracing produces a dictionary with
both `instruction` and `register` entries.

## Application examples

In the case of hardware wallets for example, one could check that:
- The PIN verification procedure does not allow to use a bad password even with a controlled instruction skip
- The scalar multiplication procedure does not leak any information on the used scalar
- a purely software AES is protected against basic DPA attacks
without using lab testing equipment (oscilloscope, current/EM probes, ...)

Rainbow and Lascar allow testing implemented countermeasures were correctly coded and the compiler did not interfere. It cannot, however, verify against hardware-related leaks such as some sequence of operations that somehow cancels out random masks on a bus or hidden register.

## Bonus applications

Whiteboxed encryption primitives could also be broken using this tool, instead of e.g. Intel Pin or Valgrind to trace execution. Unicorn has several advantages in this regard:

- Can be used on a different platform than that of the target binary
- Allows easy manipulation of the state (for example redefining an external call to `rand()` in Python)

Disadvantages:

- Some reverse engineering necessary !

As a whitebox example (available in `examples/OAES`, below is the result of the variance of [SECCON 2016's OAES](https://github.com/SECCON/SECCON2016_online_CTF/tree/master/Binary/500_Obfuscated%20AES) encryption function, which has a heavy control flow obfuscation.
One can clearly see the 10 rounds of the AES despite this obfuscation:

![OAES Variance](./OAES_variance.jpg)


## Supported archs

Embedded devices:
- STM32F215
- STM32l431

Generic emulators:
- ARM
- ARM Cortex M
- x86
- x86_64
- M68K

File formats:
- ELF
- Intel Hex file
- PE
