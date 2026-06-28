## ELF static analyzer script written in Python
This script extracts metadata, structural information, emulated checksec mitigations, and entry-point disassembly without executing any external system binaries, outputting everything as a JSON object.

### Prerequisites
The script was written in Python 3.14.5 and relies on several third-party libraries to emulate the functionality of standard linux reverse-engineering tools (file, strings, objdump, readelf).

#### 1. System dependenices
`python-magic` library requires libmagic library:
```
Debian/Ubuntu: sudo apt install libmagic1
Fedora: sudo dnf install file-libs
macOS: brew install libmagic
```
#### 2. Python dependenices
Install the following python packages using pip:
```
pip install pyelftools capstone python-magic
```

### Usage
The script only takes a single argument - path to the target ELF file
```
python3 elf_analyzer.py
```

### JSON Output Contents

The script generates a comprehensive JSON object containing the following keys:

* filename (string): The base name of the analyzed file.

* filepath (string): The absolute path to the analyzed file.

* file_size_bytes (integer): The exact size of the file on disk.

* metadata (object):

    * hashes: MD5, SHA-1, and SHA-256 cryptographic hashes.

    * magic_type: Textual file description (via libmagic).

    * mime_type: The MIME type of the file.

* header (object): Information from the ELF Header (Magic bytes, Class [32/64-bit], Data Encoding, OS ABI, Machine Architecture, and Virtual Entry Point).

* sections (array): List of all ELF sections (e.g., .text, .rodata), detailing their memory addresses, sizes in bytes, and individual entropy scores.

* segments (array): List of all ELF program headers (PT_LOAD, PT_DYNAMIC, etc.), detailing how the file is mapped into memory and memory protection flags.

* libraries (array): List of dynamically linked shared libraries required by the binary (parsed from DT_NEEDED tags).

* symbols (object):

    * imported: Functions the binary requests from external libraries (e.g., printf from libc).

    * exported: Global functions the binary offers to other programs (if it's a shared object).

    * internal: Internal debugging symbols, if the binary is unstripped.

* disassembly (object): Emulation of objdump. Contains the detected architecture, mode, and an array of the first 50 decoded assembly instructions starting precisely at the entry point.

* strings_analysis (object): Emulation of strings. Contains an array of contiguous ASCII characters (length >= 6) found in the raw binary. Capped at 2,000 strings to prevent JSON bloat, indicated by the truncated boolean.

* security_mitigations (object): Emulation of checksec.

    * nx: Boolean indicating if the stack is non-executable.

    * pie: Boolean indicating Position Independent Executable status.

    * relro: String indicating "No RELRO", "Partial RELRO", or "Full RELRO".

    * stack_canary: Boolean indicating if stack smashing protectors are present.

* build_id (string or null): The unique GNU Build ID extracted from the .note.gnu.build-id section.

* compiler_info (array): Information regarding the compiler version used to build the binary, extracted from the .comment section.

* error (string): This key will only exist if a fatal parsing error occurred, detailing why the analysis failed.

### Example
Example ELF binary taken from [TryHackMe](https://tryhackme.com/room/reverselfiles) (crackme2), as well as example json output for the same binary can be found in the [example](https://github.com/reservoir-sandbox/reverse/tree/main/example) folder.
