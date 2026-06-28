#!/usr/bin/env python3
import json
import sys
import hashlib
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Third-party imports
try:
    import magic
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection, NoteSection
    from elftools.common.exceptions import ELFError
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64
except ImportError as e:
    print(json.dumps({"error": f"Please install via pip: {e}"}))
    sys.exit(1)

def safe_str(val: Any) -> str:
    if isinstance(val, bytes):
        return val.decode('utf-8', errors='replace')
    return str(val)

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def get_file_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def extract_build_id(elf: ELFFile) -> Optional[str]:
    for section in elf.iter_sections():
        if isinstance(section, NoteSection):
            for note in section.iter_notes():
                if note['n_name'] == 'GNU' and note['n_type'] == 'NT_GNU_BUILD_ID':
                    return note['n_desc']
    return None

def extract_compiler_info(elf: ELFFile) -> List[str]:
    compilers = set()
    comment_sec = elf.get_section_by_name('.comment')
    if comment_sec:
        data = comment_sec.data().decode('utf-8', errors='ignore')
        for part in data.split('\x00'):
            if part.strip():
                compilers.add(part.strip())
    return list(compilers)

    # Check for standard binary exploit mitigations
def analyze_security_mitigations(elf: ELFFile, symbols_dict: Dict[str, List[Dict]]) -> Dict[str, Any]:
    mitigations = {
        "nx": False,
        "pie": False,
        "relro": "No RELRO",
        "stack_canary": False
    }
    
    # Non-executable stack (nx)
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_STACK':
            # PF_X (executable) flag is 1
            if not (segment['p_flags'] & 1): 
                mitigations["nx"] = True
            break
            
    # Position independent executable (pie)
    if elf.header['e_type'] == 'ET_DYN':
        mitigations["pie"] = True
        
    # Relocation read-only (relro)
    has_relro = any(seg['p_type'] == 'PT_GNU_RELRO' for seg in elf.iter_segments())
    bind_now = False
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == 'DT_BIND_NOW':
                bind_now = True
            elif tag.entry.d_tag == 'DT_FLAGS' and (tag.entry.d_val & 0x8): # DF_BIND_NOW
                bind_now = True
            elif tag.entry.d_tag == 'DT_FLAGS_1' and (tag.entry.d_val & 0x1): # DF_1_NOW
                bind_now = True
                
    if has_relro:
        mitigations["relro"] = "Full RELRO" if bind_now else "Partial RELRO"
        
    # Stack canary
    all_symbols = symbols_dict.get("imported", []) + symbols_dict.get("internal", [])
    for sym in all_symbols:
        if "__stack_chk_fail" in sym["name"]:
            mitigations["stack_canary"] = True
            break
            
    return mitigations

    # Emulate 'strings' cmd and limit output
def extract_strings(data: bytes, min_length: int = 6, max_strings: int = 2000) -> Dict[str, Any]:
    # Regex looks for contiguous printable ASCII characters
    pattern = re.compile(b'[ -~]{%d,}' % min_length)
    matches = pattern.findall(data)
    
    # Decode, deduplicate and limit
    decoded_strings = list({m.decode('ascii', errors='ignore') for m in matches})
    
    return {
        "total_unique_strings_found": len(decoded_strings),
        "strings": decoded_strings[:max_strings],
        "truncated": len(decoded_strings) > max_strings
    }

def get_capstone_disassembler(elf: ELFFile) -> Optional[Cs]:
    arch = elf.header['e_machine']
    
    if arch == 'EM_X86_64':
        return Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 'EM_386':
        return Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'EM_ARM':
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == 'EM_AARCH64':
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == 'EM_MIPS':
        elf_class = elf.header['e_ident']['EI_CLASS']
        mode = CS_MODE_MIPS64 if elf_class == 'ELFCLASS64' else CS_MODE_MIPS32
        return Cs(CS_ARCH_MIPS, mode)
    return None


    # Emulate 'objdump -d'
def disassemble_entry_point(elf: ELFFile, raw_data: bytes, max_instructions: int = 50) -> Dict[str, Any]:
    entry_point = elf.header.get('e_entry', 0)
    if entry_point == 0:
        return {"error": "No entry point defined"}

    md = get_capstone_disassembler(elf)
    if not md:
        return {"error": f"Unsupported architecture for disassembly: {elf.header['e_machine']}"}

    # Find which segment contains the entry point to translate vaddr to file offset
    entry_offset = -1
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            vaddr = segment['p_vaddr']
            memsz = segment['p_memsz']
            if vaddr <= entry_point < vaddr + memsz:
                entry_offset = entry_point - vaddr + segment['p_offset']
                break

    if entry_offset == -1:
        return {"error": "Entry point does not map to any loadable segment"}

    # Extract bytes starting from the entry point
    code_chunk = raw_data[entry_offset:entry_offset + (max_instructions * 15)]
    
    instructions = []
    try:
        for i in md.disasm(code_chunk, entry_point):
            instructions.append({
                "address": hex(i.address),
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "bytes": i.bytes.hex()
            })
            if len(instructions) >= max_instructions:
                break
    except Exception as e:
        return {"error": f"Disassembly failed: {str(e)}"}

    return {
        "architecture": md.arch,
        "mode": md.mode,
        "entry_point_vaddr": hex(entry_point),
        "instructions": instructions
    }

def analyze_elf(filepath: Path) -> Dict[str, Any]:
    try:
        raw_data = filepath.read_bytes()
    except IOError as e:
        return {"error": f"Failed to read file: {e}"}

    analysis_results: Dict[str, Any] = {
        "filename": filepath.name,
        "filepath": str(filepath.absolute()),
        "file_size_bytes": len(raw_data),
        "metadata": {},
        "header": {},
        "sections": [],
        "segments": [],
        "libraries": [],
        "symbols": {"imported": [], "exported": [], "internal": []},
        "disassembly": {},
        "strings_analysis": {},
        "security_mitigations": {},
        "build_id": None,
        "compiler_info": []
    }

    analysis_results["metadata"]["hashes"] = get_file_hashes(raw_data)
    analysis_results["metadata"]["overall_entropy"] = calculate_entropy(raw_data)
    try:
        analysis_results["metadata"]["magic_type"] = magic.from_buffer(raw_data)
        analysis_results["metadata"]["mime_type"] = magic.from_buffer(raw_data, mime=True)
    except Exception as e:
        analysis_results["metadata"]["magic_type"] = f"libmagic error: {e}"

    analysis_results["strings_analysis"] = extract_strings(raw_data, min_length=6, max_strings=2000)

    try:
        with filepath.open('rb') as f:
            elf = ELFFile(f)

            header = elf.header
            analysis_results["header"] = {
                "magic": safe_str(header.get('e_ident', {}).get('EI_MAG', '')),
                "class": safe_str(header.get('e_ident', {}).get('EI_CLASS', '')),
                "data_encoding": safe_str(header.get('e_ident', {}).get('EI_DATA', '')),
                "os_abi": safe_str(header.get('e_ident', {}).get('EI_OSABI', '')),
                "type": safe_str(header.get('e_type', '')),
                "machine": safe_str(header.get('e_machine', '')),
                "entry_point": hex(header.get('e_entry', 0))
            }

            analysis_results["disassembly"] = disassemble_entry_point(elf, raw_data, max_instructions=50)

            for section in elf.iter_sections():
                analysis_results["sections"].append({
                    "name": safe_str(section.name),
                    "type": safe_str(section['sh_type']),
                    "address": hex(section['sh_addr']),
                    "size_bytes": section['sh_size'],
                    "entropy": calculate_entropy(section.data()),
                })

            for segment in elf.iter_segments():
                analysis_results["segments"].append({
                    "type": safe_str(segment['p_type']),
                    "virtual_address": hex(segment['p_vaddr']),
                    "memory_size_bytes": segment['p_memsz'],
                    "flags": hex(segment['p_flags'])
                })

            dynamic_section = elf.get_section_by_name('.dynamic')
            if isinstance(dynamic_section, DynamicSection):
                for tag in dynamic_section.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        analysis_results["libraries"].append(safe_str(tag.needed))

            dynsym = elf.get_section_by_name('.dynsym')
            if dynsym:
                for symbol in dynsym.iter_symbols():
                    if not symbol.name:
                        continue
                        
                    sym_info = {
                        "name": safe_str(symbol.name),
                        "value": hex(symbol['st_value']),
                        "type": safe_str(symbol['st_info']['type']),
                        "bind": safe_str(symbol['st_info']['bind'])
                    }
                    
                    # SHN_UNDEF in the dynamic symbol table indicates an external import
                    if symbol['st_shndx'] == 'SHN_UNDEF':
                        analysis_results["symbols"]["imported"].append(sym_info)
                    # Global or weak symbols defined in the binary are exported
                    elif sym_info["bind"] == "STB_GLOBAL" and symbol['st_shndx'] != 'SHN_UNDEF':
                        analysis_results["symbols"]["exported"].append(sym_info)
                    elif sym_info["name"]:
                        analysis_results["symbols"]["internal"].append(sym_info)

            analysis_results["build_id"] = extract_build_id(elf)
            
            analysis_results["compiler_info"] = extract_compiler_info(elf)

            analysis_results["security_mitigations"] = analyze_security_mitigations(elf, analysis_results["symbols"])

    except ELFError as e:
        analysis_results["error"] = f"File is not a valid ELF or is corrupted: {e}"
    except Exception as e:
        analysis_results["error"] = f"An unexpected parsing error occurred: {e}"

    return analysis_results

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python3 elf_analyzer.py <path_to_elf_file>"}))
        sys.exit(1)

    target_file = Path(sys.argv[1])
    
    if not target_file.exists() or not target_file.is_file():
        print(json.dumps({"error": f"File not found: {target_file}"}))
        sys.exit(1)

    results = analyze_elf(target_file)
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
