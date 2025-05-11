# This file is part of rainbow
#
# rainbow is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# Copyright 2019 Victor Servant, Ledger SAS
import sys

from pygments import highlight
from pygments.formatters import NullFormatter, TerminalFormatter
from pygments.lexers.asm import NasmLexer

# Use colors only if tty support ANSI colors
ASM_HL = NasmLexer()
ASM_FMT = NullFormatter(outencoding="utf-8")
FOREGROUND_COLORS = {}
if sys.stdout.isatty():
    ASM_FMT = TerminalFormatter(outencoding="utf-8")
    FOREGROUND_COLORS = {
        "BLACK": "\u001b[30m",
        "RED": "\u001b[31m",
        "GREEN": "\u001b[32m",
        "YELLOW": "\u001b[33m",
        "BLUE": "\u001b[34m",
        "MAGENTA": "\u001b[35m",
        "CYAN": "\u001b[36m",
        "WHITE": "\u001b[37m",
        "_RST": "\u001b[0m",
    }


def color(color_name: str, x: str) -> str:
    """Color string `x` with color `color_name`"""
    color_code = FOREGROUND_COLORS.get(color_name, "")
    rst_code = FOREGROUND_COLORS.get("_RST", "")
    return f"{color_code}{x}{rst_code}"


def highlight_asmline(addr: int, ins: str, op_str: str):
    """Pretty-print assembly using pygments syntax highlighting"""
    line = highlight(f"{ins:<6}  {op_str:<20}", ASM_HL, ASM_FMT).decode().strip("\n")
    print("\n" + color("YELLOW", f"{addr:8X}  ") + line, end=";")
