# Async ELF Static Analysis Worker

A robust, cloud-native Python worker for static analysis of Executable and Linkable Format (ELF) files. This script extracts metadata, structural information, emulated checksec mitigations, and entry-point disassembly without executing any external system binaries.

Designed for automated pipelines, the script asynchronously downloads binaries from AWS S3, analyzes them safely using memory-mapping and chunking, and reports the findings back to a central API backend via a webhook callback.

### Prerequisites

The script requires **Python 3.12+** (tested on 3.14.5) and relies on several third-party libraries to handle async network I/O and emulate standard Linux reverse-engineering tools (`file`, `strings`, `objdump`, `readelf`).

#### 1. System Dependencies

The `python-magic` library requires the C-based `libmagic` library to be installed on the host system or Docker container:

* **Debian/Ubuntu:** `sudo apt install libmagic1`

* **Fedora/RHEL:** `sudo dnf install file-libs`

* **macOS:** `brew install libmagic`

#### 2. Python Dependencies

Install the required python packages using pip (or via the provided `requirements.txt`):

```bash
pip install pyelftools "capstone>=5.0.9" python-magic aioboto3 aiohttp

```

*(Note: `capstone` is strictly pinned to `>=5.0.9` to ensure compatibility with Python 3.12+ by dropping the deprecated `distutils` module).*

### Configuration (Environment Variables)

All execution context is provided via environment variables:

| **Variable** | **Description** |
| --- | --- |
| `S3_ACCESS_KEY` | AWS IAM access key for the S3 bucket. |
| `S3_SECRET_KEY` | AWS IAM secret key for the S3 bucket. |
| `S3_ENDPOINT_URL` | The endpoint URL for the S3 service. |
| `S3_BUCKET_NAME` | The name of the S3 bucket storing the binaries. |
| `S3_OBJECT_KEY` | The exact path/key of the target ELF binary in the bucket. |
| `TASK_ID` | The internal job/task integer ID assigned by the backend. |
| `BACKEND_CALLBACK_URL` | The base URL of the backend API (e.g., `http://backend`). |
| `WORKER_CALLBACK_SECRET` | The shared secret used to authenticate the webhook POST request. |

### Usage

Once the environment variables are set in your shell or container orchestrator, simply execute the script:

```bash
python3 elf_analyzer.py

```

### Webhook Callback & JSON Payload

The script sends a `POST` request to `/api/v1/internal/tasks/{TASK_ID}/callback`. It authenticates using the `X-Worker-Token` header.

The payload follows the **TaskCallback** schema. If the analysis is under 1MB, the ELF data is sent inline under the `result` key. If it exceeds 1MB, the JSON is uploaded to S3, and the `report_object_name` key is provided instead.

#### Top-Level Payload Schema

* `status` (string): `completed` or `failed`.
* `started_at` (string): ISO-8601 UTC start time of the analysis.
* `finished_at` (string): ISO-8601 UTC end time of the analysis.
* `error` (string | null): Fatal error message if the analysis crashed or timed out.
* `report_object_name` (string | null): The S3 key of the report (e.g., `reports/123_report.json`), if the payload exceeded 1MB.
* `result` (object | null): The comprehensive ELF analysis dictionary (if under 1MB).

#### The `result` Object (ELF Analysis Data)

If provided inline, the `result` object contains the following keys:

* `filename` (string): The base name of the analyzed file (extracted from the S3 key).
* `filepath` (string): The temporary local path used by the worker (e.g., `/tmp/123.elf`).
* `file_size_bytes` (integer): The exact size of the file on disk.
* `metadata` (object):
* `hashes`: MD5, SHA-1, and SHA-256 cryptographic hashes.
* `overall_entropy`: Shannon entropy (0.0 to 8.0). High values (> 7.0) indicate packing or encryption.
* `magic_type`: Textual file description (via libmagic).
* `mime_type`: The MIME type of the file.


* `header` (object): Information from the ELF Header (Magic bytes, Class 
$$32/64-bit$$


, Data Encoding, OS ABI, Machine Architecture, and Virtual Entry Point).
* `sections` (array): List of all ELF sections (e.g., `.text`, `.rodata`), detailing their memory addresses, sizes in bytes, and individual entropy scores.
* `segments` (array): List of all ELF program headers (PT_LOAD, PT_DYNAMIC, etc.), detailing how the file is mapped into memory and memory protection flags.
* `libraries` (array): List of dynamically linked shared libraries required by the binary (parsed from DT_NEEDED tags).
* `symbols` (object):
* `imported`: Functions the binary requests from external libraries (e.g., `printf` from libc).
* `exported`: Global functions the binary offers to other programs (if it's a shared object).
* `internal`: Internal debugging symbols, if the binary is unstripped.


* `disassembly` (object): Emulation of objdump. Contains the detected architecture, mode, and an array of the first 50 decoded assembly instructions starting precisely at the entry point.
* `strings_analysis` (object): Emulation of strings. Contains an array of contiguous ASCII characters (length >= 6) found in the raw binary. Capped at 2,000 strings to prevent JSON bloat, indicated by the truncated boolean.
* `security_mitigations` (object): Emulation of checksec.
* `nx`: Boolean indicating if the stack is non-executable.
* `pie`: Boolean indicating Position Independent Executable status.
* `relro`: String indicating "No RELRO", "Partial RELRO", or "Full RELRO".
* `stack_canary`: Boolean indicating if stack smashing protectors are present.


* `build_id` (string | null): The unique GNU Build ID extracted from the `.note.gnu.build-id` section.
* `compiler_info` (array): Information regarding the compiler version used to build the binary, extracted from the `.comment` section.

### Example

An example ELF binary taken from [TryHackMe](https://tryhackme.com/room/reverselfiles) (`crackme2`), as well as an example JSON payload generated by this worker for that specific binary, can be found in the [example](https://github.com/reservoir-sandbox/reverse/tree/main/example) folder.
