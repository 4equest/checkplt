import sys
import json
import struct
import argparse
import pygments.lexers.asm
from elftools.elf.elffile import ELFFile
from capstone import *
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

def detect_tampered_linking(elf_file_path):
    with open(elf_file_path, 'rb') as file:
        elffile = ELFFile(file)
        
        relaplt = elffile.get_section_by_name('.rela.plt')
        dynsym = elffile.get_section_by_name('.dynsym')
        got = elffile.get_section_by_name('.got')
        plt = elffile.get_section_by_name('.plt')
        plt_sec = elffile.get_section_by_name('.plt.sec')
        got_plt = elffile.get_section_by_name('.got.plt')
        
        if plt is None:
            console.print("[bold red]no .plt section")
            sys.exit(1)
        if got_plt is None:
            console.print("[bold yellow]no .got.plt section")
            console.print("[bold yellow]maybe not lazy binding?")
            
        if plt and plt_sec is None:
            plt_stub_instructions = get_plt_target(plt.header.sh_addr, plt.data())
        elif got_plt and plt_sec:
            plt_stub_instructions = get_plt_sec_target(plt.header.sh_addr, plt.data(), plt_sec.header.sh_addr, plt_sec.data(), got_plt.header.sh_addr, got_plt.data())
        elif got and plt_sec:
            plt_stub_instructions = get_plt_sec_target(plt.header.sh_addr, plt.data(), plt_sec.header.sh_addr, plt_sec.data(), got.header.sh_addr, got.data())
        else:
            console.print("[bold red]no .got.plt and .plt.sec section")
            sys.exit(1)

        if len(plt_stub_instructions) != int(relaplt.data_size / relaplt.entry_size):
            console.print(f"[bold yellow]dynamic linking count {len(plt_stub_instructions)} != .rela.plt entry count {int(relaplt.data_size / relaplt.entry_size)}")

        relaplt_table = Table(title=".rela.plt")
        relaplt_table.add_column("", justify="center", style="cyan bold")
        relaplt_table.add_column("symbol", justify="left", style="cyan")
        relaplt_table.add_column("r_offset", justify="left", style="green")
        relaplt_table.add_column("r_info", justify="left", style="cyan")
        relaplt_table.add_column("type", justify="left", style="cyan")
        console.print(relaplt_table)
        
        results = []
        for idx, rel in enumerate(relaplt.iter_relocations()):
            symbol = dynsym.get_symbol(rel.entry.r_info_sym)
            symbol_name = symbol.name
            relaplt_table.add_row(str(idx), f"{rel.entry.r_info_sym}({symbol_name})", hex(rel.entry.r_offset), hex(rel.entry.r_info), hex(rel.entry.r_info_type))
            # r_offsetがpltスタブ内のjmp命令のジャンプ先と一致するか確認
            if len(plt_stub_instructions) > idx:
                jmp_target = next((instruction['jmp_target'] for instruction in plt_stub_instructions if instruction['push_value'] == idx))
                if rel.entry.r_offset != jmp_target:
                    results.append({"tampered": True, "index": idx, "symbol": symbol_name, "dynamic": jmp_target, "r_offset": rel.entry.r_offset})
                else:
                    results.append({"tampered": False, "index": idx, "symbol": symbol_name, "dynamic": jmp_target, "r_offset": rel.entry.r_offset})
                    
        return results
        

def get_plt_target(plt_start, plt_data):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    plt_stub_instructions = []
    disasm_result = []
    instructions = list(md.disasm(plt_data, plt_start))
    for i in range(len(instructions)-2):
        op_str = instructions[i].op_str
        if instructions[i].mnemonic == 'jmp' and instructions[i+1].mnemonic == 'push' and instructions[i+2].mnemonic == 'jmp':
            jmp_target = instructions[i].disp + instructions[i+1].address
            push_value = instructions[i+1].operands[0].imm
            plt_stub_instructions.append({'jmp_target': jmp_target, 'push_value': push_value})
            disasm_result.append(f"{hex(instructions[i].address)} {instructions[i].mnemonic} {op_str} -> [{hex(jmp_target)}]")
        else:
            disasm_result.append(f"{hex(instructions[i].address)} {instructions[i].mnemonic} {op_str}")

    console.print(Panel(Syntax("\n".join(disasm_result), lexer=pygments.lexers.asm.CObjdumpLexer()), title=".plt", expand=False))
    return plt_stub_instructions

def get_plt_sec_target(plt_start, plt_data, plt_sec_start, plt_sec_data, got_start, got_data):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    plt_stub_instructions = []
    disasm_result = []
    plt_sec_instructions = list(md.disasm(plt_sec_data, plt_sec_start))
    plt_instructions = list(md.disasm(plt_data, plt_start))
    for i in range(len(plt_sec_instructions)):
        op_str = plt_sec_instructions[i].op_str
        if plt_sec_instructions[i].mnemonic == 'bnd jmp' and plt_sec_instructions[i+1].mnemonic == 'nop':
            jmp_target = plt_sec_instructions[i].disp + plt_sec_instructions[i+1].address
            got_plt_jmp_address = struct.unpack('<Q', got_data[jmp_target - got_start: jmp_target - got_start + 8])[0]
            for j in range(len(plt_instructions)):
                if plt_instructions[j].address == got_plt_jmp_address:
                    if plt_instructions[j].mnemonic == 'push':
                        push_value = plt_instructions[j].operands[0].imm
                        plt_stub_instructions.append({'jmp_target': jmp_target, 'push_value': push_value})
                        disasm_result.append(f"{hex(plt_sec_instructions[i].address)} {plt_sec_instructions[i].mnemonic} {op_str} -> [{hex(jmp_target)}] -> (.plt){hex(got_plt_jmp_address)} {plt_instructions[j].mnemonic} {push_value}")
                    elif plt_instructions[j+1].mnemonic == 'push':
                        push_value = plt_instructions[j+1].operands[0].imm
                        plt_stub_instructions.append({'jmp_target': jmp_target, 'push_value': push_value})
                        disasm_result.append(f"{hex(plt_sec_instructions[i].address)} {plt_sec_instructions[i].mnemonic} {op_str} -> [{hex(jmp_target)}] -> (.plt){hex(got_plt_jmp_address)} {plt_instructions[j].mnemonic} (.plt){hex(plt_instructions[j+1].address)} {plt_instructions[j+1].mnemonic} {push_value}")
                    else:
                        disasm_result.append(f"{hex(plt_sec_instructions[i].address)} {plt_sec_instructions[i].mnemonic} {op_str}")
        else:
            disasm_result.append(f"{hex(plt_sec_instructions[i].address)} {plt_sec_instructions[i].mnemonic} {op_str}")
                    
    console.print(Panel(Syntax("\n".join(disasm_result), lexer=pygments.lexers.asm.CObjdumpLexer()), title=".plt.sec", expand=False))

    return plt_stub_instructions

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check plt ^_-')
    parser.add_argument('elf_file_path', type=str, help='Path to the ELF file')
    parser.add_argument('--json', action='store_true', help='Print JSON if specified')

    args = parser.parse_args()
    
    console = Console()

    results = detect_tampered_linking(args.elf_file_path)
    
    if not args.json:
        result_table = Table(title="[bold]Result")
        result_table.add_column("", justify="center", style="cyan bold")
        result_table.add_column("symbol", justify="left", style="cyan")
        result_table.add_column("dynamic", justify="left", style="green")
        result_table.add_column("", justify="center", style="dim")
        result_table.add_column("r_offset", justify="left", style="green")
        for result in results:
            if result["tampered"] :
                result_table.add_row(f"[red]{str(result['index'])}", f"[red bold]{result['symbol']}", hex(result["dynamic"]), "->", f"[red bold]{hex(result['r_offset'])}({next(result_['symbol'] for result_ in results if result['r_offset'] == result_['dynamic'])})")
            else:
                result_table.add_row(str(result['index']), result["symbol"], hex(result["dynamic"]), "->", hex(result["r_offset"]))

        console.print(result_table)
    else:
        print(json.dumps(results, indent=4))
