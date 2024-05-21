# Why is this necessary?

Some elf file malware replaces dynamically linked function names with other names by rewriting .plt and rela.plt sections to prevent analysis. This involves a variety of factors, including lazy binding and changing the r_offset in the .rela.plt section.
Threat actors want analysts to be unaware of this and blindly trust disassemblers such as gdb or sophisticated decompilers such as IDA.
Do you understand the capabilities of the tools you use? This simple analysis tool can detect these tricks.

# Usage

Simply run the python file with the file name.
```
python3 checkplt.py . /elf
```
You will then get the following output.
```
╭─────────────────────── .plt ───────────────────────╮
│ 0x660 push qword ptr [rip + 0x2009a2]              │
│ 0x666 jmp qword ptr [rip + 0x2009a4]               │
│ 0x66c nop dword ptr [rax]                          │
│ 0x670 jmp qword ptr [rip + 0x2009a2] -> [0x201018] │
│ 0x676 push 0                                       │
│ 0x67b jmp 0x660                                    │
│ 0x680 jmp qword ptr [rip + 0x20099a] -> [0x201020] │
│ 0x686 push 1                                       │
│ 0x68b jmp 0x660                                    │
│ 0x690 jmp qword ptr [rip + 0x200992] -> [0x201028] │
│ 0x696 push 2                                       │
│ 0x69b jmp 0x660                                    │
│ 0x6a0 jmp qword ptr [rip + 0x20098a] -> [0x201030] │
╰────────────────────────────────────────────────────╯
                         .rela.plt
┏━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━┓
┃   ┃ symbol               ┃ r_offset ┃ r_info      ┃ type ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━┩
│ 0 │ 2(strncmp)           │ 0x201030 │ 0x200000007 │ 0x7  │
│ 1 │ 4(puts)              │ 0x201020 │ 0x400000007 │ 0x7  │
│ 2 │ 5(__libc_start_main) │ 0x201028 │ 0x500000007 │ 0x7  │
│ 3 │ 6(strcmp)            │ 0x201018 │ 0x600000007 │ 0x7  │
└───┴──────────────────────┴──────────┴─────────────┴──────┘
                           Result
┏━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃   ┃ symbol            ┃ dynamic  ┃    ┃ r_offset          ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ 0 │ strncmp           │ 0x201018 │ -> │ 0x201030(strcmp)  │
│ 1 │ puts              │ 0x201020 │ -> │ 0x201020          │
│ 2 │ __libc_start_main │ 0x201028 │ -> │ 0x201028          │
│ 3 │ strcmp            │ 0x201030 │ -> │ 0x201018(strncmp) │
└───┴───────────────────┴──────────┴────┴───────────────────┘
```
