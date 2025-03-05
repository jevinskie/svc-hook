#!/usr/bin/env python3
import r2pipe
import sys
import re

from rich import print

def analyze_svc_instructions(filepath):
    # Open the binary with r2pipe
    print(f"Opening {filepath}...")
    r2 = r2pipe.open(filepath)
    
    # Analyze the binary
    print("Analyzing binary...")
    # r2.cmd("aaa")
    r2.cmd("aaaa")  # Analyze all referenced code
    r2.cmd("aaaaa")  # Analyze all referenced code
    
    # Check if it's an AArch64 binary
    info = r2.cmdj("ij")
    arch_info = info.get("bin", {})
    if arch_info.get("arch") != "arm" or arch_info.get("bits") != 64:
        print(f"Warning: This may not be an AArch64 binary. Detected: {arch_info.get('arch')}/{arch_info.get('bits')}")
    
    # Search for SVC instructions
    print("Searching for SVC instructions...")

    svc_imms: set[int] = set()
    x16_imms: set[int] = set()
    next_insns: set[str] = set()


    # Use /a to search for SVC assembly instructions
    # r2.cmd("e search.in=exec")  # Search only in executable sections
    text_section = r2.cmdj("iSj")[0]
    print("text_section")
    print(text_section)

    r2.cmd(f"e search.from={text_section['vaddr']:#x}")
    r2.cmd(f"e search.to={text_section['vaddr'] + text_section['vsize']:#x}")
    hits =r2.cmdj("/amj svc")["result"]  # Search for SVC instructions
    print(hits)

    # Get the search results
    # hits = r2.cmdj("/?j")
    
    if not hits:
        print("No SVC instructions found in the binary.")
        r2.quit()
        return
    
    print(f"Found {len(hits)} SVC instructions")
    print("-" * 80)
    
    # Process each SVC instruction
    for hit in hits:
        addr = hit["addr"]
        
        # Disassemble the SVC instruction to get the immediate
        svc_instr = r2.cmdj(f"pdj 1 @ {addr}")
        
        if not svc_instr or len(svc_instr) == 0:
            continue
            
        svc_opcode = svc_instr[0].get("opcode", "unknown")
        
        # Extract SVC immediate
        svc_imm = None
        svc_match = re.search(r'svc\s+#?([-]?0x[0-9a-fA-F]+|[-]?\d+)', svc_opcode)
        if svc_match:
            svc_imm = svc_match.group(1)
            svc_imm = int(svc_imm, base=16)
            svc_imms.add(svc_imm)
        
        # Get previous instruction to check for x16 immediate
        prev_instr = r2.cmdj(f"pdj 1 @ {addr-4}")
        x16_imm = None
        prev_opcode = "unknown"
        
        if prev_instr and len(prev_instr) > 0:
            prev_opcode = prev_instr[0].get("opcode", "unknown")
            
            # Look for any instruction that loads a value into x16
            if "x16" in prev_opcode or "w16" in prev_opcode:
                x16_pattern = r'\s+[wx]16,\s+(-?0x[0-9a-fA-F]+|-?\d+)'
                x16_match = re.search(x16_pattern, prev_opcode)
                if x16_match:
                    x16_imm = x16_match.group(1)
                    x16_imm = int(x16_imm, base=16)
                    if x16_imm in x16_imms:
                        print(f"x16_imm {x16_imm:#x} is a DUPE")
                    x16_imms.add(x16_imm)
        
        # Get next instruction after SVC
        next_instr = r2.cmdj(f"pdj 1 @ {addr+4}")
        next_opcode = "unknown"
        
        if next_instr and len(next_instr) > 0:
            next_opcode = next_instr[0].get("opcode", "unknown")
            next_opcode = next_opcode.split()[0]
            next_insns.add(next_opcode)
        
        # Print the information in a formatted way
        print(f"Address:              0x{addr:x}")
        # print(f"SVC Instruction:      {svc_opcode}")
        # print(f"SVC Immediate:        {svc_imm if svc_imm else 'Not found'}")
        print(f"Previous Instruction: {prev_opcode}")
        print(f"x16 Immediate:        {x16_imm if x16_imm is not None else 'Not found'}")
        print(f"Next Instruction:     {next_opcode}")
        print("-" * 80)
    print(f"svc_imms: len: {len(svc_imms)}")
    print(svc_imms)
    print(f"x16_imms: len: {len(x16_imms)}")
    print(x16_imms)
    print(f"next_insns: len: {len(next_insns)}")
    print(next_insns)

    r2.quit()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <mach-o file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    analyze_svc_instructions(filepath)