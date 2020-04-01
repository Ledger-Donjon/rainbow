from .utils import hw

def regs_hw_sum_trace(rbw, address, size, data):
    ins = rbw.reg_leak
    if ins is not None:
      _, regs_written = ins.regs_access()
      v = sum(hw(rbw.emu.reg_read(rbw.reg_map[ins.reg_name(i)])) for i in regs_written)

      rbw.sca_address_trace.append( f"{address:8X} {ins.mnemonic:<6}  {ins.op_str}" )
      rbw.sca_values_trace.append(v)

    rbw.reg_leak = rbw.disassemble_single_detailed(address, size)

def wb_regs_trace(rbw, address, size, data):
    """One point per register value, and filter out uninteresting register accesses"""
    if rbw.reg_leak:
      ins = rbw.reg_leak[0]
      for reg in map(ins.reg_name, rbw.reg_leak[1]):
          if reg not in rbw.TRACE_DISCARD:
            rbw.sca_address_trace.append(ins)
            rbw.sca_values_trace.append(rbw.emu.reg_read(rbw.reg_map[reg]))

    rbw.reg_leak = None

    ins = rbw.disassemble_single_detailed(address, size)
    _regs_read, regs_written = ins.regs_access()
    if len(regs_written) > 0:
        rbw.reg_leak = (ins, regs_written) 