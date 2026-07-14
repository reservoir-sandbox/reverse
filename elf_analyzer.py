#!/usr/bin/env python3
import json
import sys
import hashlib
import math
import re
import os
import asyncio
import mmap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Third-party imports
try:
    import magic
    import aioboto3
    import aiohttp
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

def get_hashes_and_entropy_chunked(filepath: Path) -> Tuple[Dict[str, str], float, int]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    counts = [0] * 256
    total_len = 0
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(1024 * 1024): 
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            total_len += len(chunk)
            for byte in chunk:
                counts[byte] += 1
                
    entropy = 0.0
    if total_len > 0:
        for count in counts:
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
                
    hashes = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }
    return hashes, entropy, total_len

def extract_strings_mmap(mm: mmap.mmap, min_length: int = 6, max_strings: int = 2000) -> Dict[str, Any]:
    pattern = re.compile(b'[ -~]{%d,}' % min_length)
    decoded_strings = set()
    truncated = False
    
    for match in pattern.finditer(mm):
        decoded_strings.add(match.group(0).decode('ascii', errors='ignore'))
        if len(decoded_strings) >= max_strings:
            truncated = True
            break
            
    return {
        "total_unique_strings_found": len(decoded_strings),
        "strings": list(decoded_strings),
        "truncated": truncated
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

def analyze_security_mitigations(elf: ELFFile, symbols_dict: Dict[str, List[Dict]]) -> Dict[str, Any]:
    mitigations = {
        "nx": False,
        "pie": False,
        "relro": "No RELRO",
        "stack_canary": False
    }
    
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_STACK':
            if not (segment['p_flags'] & 1): 
                mitigations["nx"] = True
            break
            
    if elf.header['e_type'] == 'ET_DYN':
        mitigations["pie"] = True
        
    has_relro = any(seg['p_type'] == 'PT_GNU_RELRO' for seg in elf.iter_segments())
    bind_now = False
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == 'DT_BIND_NOW' or \
               (tag.entry.d_tag == 'DT_FLAGS' and (tag.entry.d_val & 0x8)) or \
               (tag.entry.d_tag == 'DT_FLAGS_1' and (tag.entry.d_val & 0x1)):
                bind_now = True
                
    if has_relro:
        mitigations["relro"] = "Full RELRO" if bind_now else "Partial RELRO"
        
    all_symbols = symbols_dict.get("imported", []) + symbols_dict.get("internal", [])
    for sym in all_symbols:
        if "__stack_chk_fail" in sym["name"]:
            mitigations["stack_canary"] = True
            break
            
    return mitigations

def get_capstone_disassembler(elf: ELFFile) -> Optional[Cs]:
    arch = elf.header['e_machine']
    if arch == 'EM_X86_64': return Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 'EM_386': return Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'EM_ARM': return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == 'EM_AARCH64': return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == 'EM_MIPS':
        elf_class = elf.header['e_ident']['EI_CLASS']
        mode = CS_MODE_MIPS64 if elf_class == 'ELFCLASS64' else CS_MODE_MIPS32
        return Cs(CS_ARCH_MIPS, mode)
    return None

def disassemble_entry_point(elf: ELFFile, raw_data: bytes, max_instructions: int = 50) -> Dict[str, Any]:
    entry_point = elf.header.get('e_entry', 0)
    if entry_point == 0:
        return {"error": "No entry point defined"}

    md = get_capstone_disassembler(elf)
    if not md:
        return {"error": f"Unsupported architecture for disassembly: {elf.header['e_machine']}"}

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

def analyze_elf(filepath: Path, original_filename: str) -> Dict[str, Any]:
    analysis_results: Dict[str, Any] = {
        "filename": original_filename,
        "filepath": str(filepath.absolute()),
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

    try:
        hashes, entropy, size = get_hashes_and_entropy_chunked(filepath)
        analysis_results["file_size_bytes"] = size
        analysis_results["metadata"]["hashes"] = hashes
        analysis_results["metadata"]["overall_entropy"] = entropy

        if size == 0:
            analysis_results["error"] = "File is empty"
            return analysis_results

        with filepath.open('rb') as f:
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                
                try:
                    analysis_results["metadata"]["magic_type"] = magic.from_buffer(mm[:2048])
                    analysis_results["metadata"]["mime_type"] = magic.from_buffer(mm[:2048], mime=True)
                except Exception as e:
                    analysis_results["metadata"]["magic_type"] = f"libmagic error: {e}"

                analysis_results["strings_analysis"] = extract_strings_mmap(mm, min_length=6, max_strings=2000)

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

                entry_point = header.get('e_entry', 0)
                if entry_point != 0:
                     analysis_results["disassembly"] = disassemble_entry_point(elf, mm, max_instructions=50)

                for section in elf.iter_sections():
                    sec_data = section.data()
                    entropy_val = 0.0
                    if sec_data:
                        counts = [0] * 256
                        for b in sec_data: counts[b] += 1
                        for c in counts:
                            if c > 0:
                                p = c / len(sec_data)
                                entropy_val -= p * math.log2(p)
                                
                    analysis_results["sections"].append({
                        "name": safe_str(section.name),
                        "type": safe_str(section['sh_type']),
                        "address": hex(section['sh_addr']),
                        "size_bytes": section['sh_size'],
                        "entropy": entropy_val,
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
                        if not symbol.name: continue
                        sym_info = {
                            "name": safe_str(symbol.name),
                            "value": hex(symbol['st_value']),
                            "type": safe_str(symbol['st_info']['type']),
                            "bind": safe_str(symbol['st_info']['bind'])
                        }
                        if symbol['st_shndx'] == 'SHN_UNDEF':
                            analysis_results["symbols"]["imported"].append(sym_info)
                        elif sym_info["bind"] in ("STB_GLOBAL", "STB_WEAK") and symbol['st_shndx'] != 'SHN_UNDEF':
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

def get_iso_time() -> str:
    """Returns strict ISO-8601 UTC time (e.g., 2026-07-14T20:01:43.123Z)"""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

async def main():
    # Capture start time immediately
    started_at = get_iso_time()
    
    ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
    SECRET_KEY = os.getenv("S3_SECRET_KEY")
    ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL")
    BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
    
    # Updated Env Vars
    BACKEND_CALLBACK_URL = os.getenv("BACKEND_CALLBACK_URL")
    WORKER_CALLBACK_SECRET = os.getenv("WORKER_CALLBACK_SECRET")
    TASK_ID = os.getenv("TASK_ID")
    S3_OBJECT_KEY = os.getenv("S3_OBJECT_KEY")

    if not all([ACCESS_KEY, SECRET_KEY, ENDPOINT_URL, BUCKET_NAME, BACKEND_CALLBACK_URL, WORKER_CALLBACK_SECRET, TASK_ID, S3_OBJECT_KEY]):
        print(json.dumps({"error": "Critical configuration missing from environment variables."}))
        sys.exit(1)

    if not BACKEND_CALLBACK_URL.endswith(f"/callback"):
        callback_url = f"{BACKEND_CALLBACK_URL.rstrip('/')}/api/v1/internal/tasks/{TASK_ID}/callback"
    else:
        callback_url = BACKEND_CALLBACK_URL

    http_headers = {
        "X-Worker-Token": WORKER_CALLBACK_SECRET,
        "Content-Type": "application/json"
    }

    temp_file = Path(f"/tmp/{TASK_ID}.elf")
    original_filename = Path(S3_OBJECT_KEY).name
    session = aioboto3.Session()
    
    try:
        async with session.client(
            "s3", endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY
        ) as s3:
            await s3.download_file(Bucket=BUCKET_NAME, Key=S3_OBJECT_KEY, Filename=str(temp_file))
        
        analysis_results = await asyncio.wait_for(
            asyncio.to_thread(analyze_elf, temp_file, original_filename),
            timeout=300.0 
        )
        
        json_string = json.dumps(analysis_results)
        payload_bytes = json_string.encode("utf-8")
        THRESHOLD_1MB = 1024 * 1024
        
        finished_at = get_iso_time()
        
        callback_payload = {
            "status": "completed",
            "started_at": started_at,
            "finished_at": finished_at
        }
        
        if len(payload_bytes) <= THRESHOLD_1MB:
            callback_payload["result"] = analysis_results
        else:
            output_report_key = f"reports/{TASK_ID}_report.json"
            async with session.client(
                "s3", endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY
            ) as s3:
                await s3.put_object(
                    Bucket=BUCKET_NAME, Key=output_report_key, Body=payload_bytes, ContentType="application/json"
                )
            callback_payload["report_object_name"] = output_report_key

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.post(callback_url, headers=http_headers, json=callback_payload) as response:
                if response.status not in [200, 201, 202, 204]:
                    print(f"Failed to post success callback. HTTP Status: {response.status}")
                    body = await response.text()
                    print(f"Backend response: {body}")

    except asyncio.TimeoutError:
        error_msg = "Analysis timed out (exceeded 5 minutes). Possible decompression bomb."
        print(error_msg)
        await send_error_callback(callback_url, http_headers, error_msg, started_at)
    except Exception as err:
        print(f"Execution Error: {err}")
        await send_error_callback(callback_url, http_headers, str(err), started_at)
        sys.exit(1)
        
    finally:
        if temp_file.exists():
            temp_file.unlink()

async def send_error_callback(url: str, headers: dict, error_msg: str, started_at: str):
    finished_at = get_iso_time()
    error_payload = {
        "status": "failed",
        "error": error_msg,
        "started_at": started_at,
        "finished_at": finished_at
    }
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            await http_session.post(url, headers=headers, json=error_payload)
    except Exception as network_err:
        print(f"Failed to deliver error callback: {network_err}")

if __name__ == "__main__":
    asyncio.run(main())