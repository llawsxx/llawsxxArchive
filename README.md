# llawsxxArchive (lxar)

> An archiving tool that stores files in chunks, supports AES-128 encryption, ZSTD compression, multi-volume splitting, and Reed-Solomon erasure coding for data recovery.
>
> 一款将文件分块储存的归档工具，支持 AES-128 加密、ZSTD 压缩、分卷和基于 Reed-Solomon 纠删码的数据恢复。

---

## Table of Contents / 目录

- [Features](#features--特性)
- [File Format](#file-format--文件格式)
- [Build](#build--编译)
- [Usage](#usage--使用方法)
  - [archive](#archive--创建归档)
  - [extract](#extract--提取文件)
  - [list](#list--列出内容)
  - [verify](#verify--验证完整性)
  - [repair](#repair--修复归档)
- [Options](#options--选项说明)
- [Examples](#examples--示例)
- [Notes](#notes--注意事项)

---

## Features / 特性

| Feature | Description |
|---------|-------------|
| **Chunked storage** | Files are split into fixed-size sections, allowing partial recovery |
| **AES-128 CBC** | Optional encryption with per-section IV derived from header CRC |
| **ZSTD compression** | Configurable compression level (1–22), skipped if data grows |
| **Multi-volume** | Split archives into volumes of any size, up to 99999 volumes |
| **Reed-Solomon** | Configurable parity shards for erasure recovery |
| **UTF-8 paths** | Full Unicode filename support on Windows |
| **CRC32 integrity** | Every section has a CRC32 checksum; headers are separately checksummed |

---

## File Format / 文件格式

Each file is stored as one or more **blocks**. Every block consists of:

```
┌─────────────────────────────────┐
│         BlockHeader             │  fixed size, big-endian
│  magic / filename / mtime /     │
│  total_size / block_id /        │
│  block_group_id / section_id /  │
│  section_size / original_size / │
│  total_section_count /          │
│  data_offset / flags /          │
│  header_crc32                   │
├─────────────────────────────────┤
│    Data  (section_size bytes)   │  encrypted and/or compressed
├─────────────────────────────────┤
│         CRC32  (4 bytes)        │  big-endian, covers Data
└─────────────────────────────────┘
```

- **Magic numbers**: `BLOC` (0x424C4F43) for files, `DIR\0` (0x44495200) for directories.
- **Flags**: `0x01` = AES encrypted, `0x02` = ZSTD compressed, `0x04` = RS redundancy block.
- **RS redundancy blocks** are appended transparently after each data group and share the same block format.

### Multi-volume naming / 分卷命名规则

```
basename.001.lxar   (volumes 1–999)
basename.1000.lxar  (volumes 1000–9999)
basename.10000.lxar (volumes 10000–99999)
```


---

## Usage / 使用方法

```
lxar <command> [options] <arguments>
```

### archive / 创建归档

```
lxar archive [-o <output>] [-s <size>] [-v <size>] [-p <password>]
             [-z <level>] [--rs <data> <parity>]
             [--rs-group-size <size>] <directory>
```

Recursively archives the specified directory.  
递归归档指定目录。

**Behavior:**
- Directories are stored as entries (preserving structure).
- Empty files and empty directories are both preserved.
- Compression is skipped per-section if compressed size ≥ original size.
- Encryption is applied **after** compression. The IV for each section is derived from its header CRC32.

---

### extract / 提取文件

```
lxar extract [-o <output_dir>] [-p <password>] <archive> [file1 file2 ...]
```

Extract all files, or only the specified files from the archive.  
提取所有文件，或仅提取指定文件。

- If no file list is given, all files are extracted.
- Paths inside the archive use forward slashes (`/`). Specify them accordingly when extracting individual files.
- Corrupted files are renamed to `<filename>.corrupted` rather than silently discarded.

---

### list / 列出内容

```
lxar list <archive>
```

Lists all files and directories stored in the archive with their metadata.  
列出归档内所有文件和目录及其元数据。

Output columns: `Name / Modified Time / Type / Size / Flags / CRC`

---

### verify / 验证完整性

```
lxar verify [-p <password>] <archive>
```

Reads every block and verifies all CRC32 checksums. Reports:  
读取每个块并验证 CRC32，输出：

- Per-block status (OK / DATA CORRUPTED)
- Missing sections
- Section count mismatches
- Final summary (intact / issues found)

---

### repair / 修复归档

```
lxar repair [-o <output>] <archive>
```

Reconstructs a new valid archive using Reed-Solomon parity blocks to recover corrupted or missing data blocks.  
使用 Reed-Solomon 校验块重建一个新的有效归档，恢复损坏或丢失的数据块。

- Requires the archive to have been created with `--rs`.
- The repaired archive is written to a new file (default: `<archive>.repaired`).
- Blocks with `block_group_id == 0` are copied verbatim (not subject to RS).

---

## Options / 选项说明

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output <path>` | auto | Output file (archive) or directory (extract/repair) |
| `-s`, `--section-size <size>` | `256K` | Size of each data section. Range: `1K` – `64M` |
| `-v`, `--volume-size <size>` | disabled | Split archive into volumes of this size. Range: `4M` – `4T`. Use `0` to disable |
| `-p`, `--password <password>` | none | Encryption password. Either a plain string (padded/truncated to 16 bytes) or a 32-character hex string (e.g. `00112233445566778899aabbccddeeff`) |
| `-z`, `--compress <level>` | `3` | ZSTD compression level `1`–`22`. Use `0` to disable compression |
| `--rs <data> <parity>` | disabled | Enable Reed-Solomon: `data` data shards + `parity` parity shards. Total must be ≤ 256 |
| `--rs-group-size <size>` | `512M` | Accumulate this much data before emitting an RS group. Range: `1M` – `1024M` |

### Size suffixes / 大小后缀

| Suffix | Multiplier |
|--------|-----------|
| `K` / `k` | × 1,024 |
| `M` / `m` | × 1,048,576 |
| `G` / `g` | × 1,073,741,824 |
| `T` / `t` | × 1,099,511,627,776 |

---

## Examples / 示例

### Basic archiving / 基本归档

```bash
# Archive a folder with default settings (ZSTD level 3, no encryption, no splitting)
lxar archive myfolder

# Specify output filename
lxar archive -o myarchive.lxar myfolder
```

### Compression / 压缩

```bash
# Maximum compression
lxar archive -z 22 -o max_compressed.lxar myfolder

# Disable compression (e.g. already-compressed media files)
lxar archive -z 0 -o no_compress.lxar myfolder
```

### Encryption / 加密

```bash
# Encrypt with a plain password
lxar archive -p "my secret password" -o encrypted.lxar myfolder

# Encrypt with a raw 16-byte hex key
lxar archive -p 00112233445566778899aabbccddeeff -o encrypted.lxar myfolder

# Extract with password
lxar extract -p "my secret password" -o output_dir encrypted.lxar
```

### Multi-volume / 分卷

```bash
# Split into 100 MB volumes → myarchive.001.lxar, myarchive.002.lxar, ...
lxar archive -v 100M -o myarchive.lxar myfolder

# Split into 1 GB volumes
lxar archive -v 1G -o myarchive.lxar myfolder

# Extract (always specify the first volume)
lxar extract -o output_dir myarchive.001.lxar
```

### Reed-Solomon redundancy / RS 冗余

```bash
# 10 data shards + 3 parity shards (can recover any 3 lost/corrupted shards per group)
lxar archive --rs 10 3 -o protected.lxar myfolder

# Smaller RS group size for finer-grained recovery
lxar archive --rs 10 3 --rs-group-size 64M -o protected.lxar myfolder

# Repair a damaged archive
lxar repair -o repaired.lxar protected.lxar

# Verify the repaired archive
lxar verify repaired.lxar
```

### Combined options / 组合选项

```bash
# 1 MB sections, 500 MB volumes, encrypted, compressed (level 9), with RS redundancy
lxar archive -s 1M -v 500M -p mypassword -z 9 --rs 8 2 -o full.lxar myfolder

# Extract from multi-volume encrypted archive
lxar extract -p mypassword -o restored myfolder.001.lxar
```

### Extract specific files / 提取指定文件

```bash
# Paths must match the in-archive path (forward slashes)
lxar extract -o output_dir archive.lxar docs/readme.txt src/main.c
```

### List and verify / 列出与验证

```bash
lxar list archive.lxar
lxar verify archive.lxar
lxar verify -p mypassword encrypted.lxar
```

---

## Notes / 注意事项

1. **Password is not verified on extract/verify.**  
   If a wrong password is provided, decryption will silently produce garbage. The data CRC will likely fail and the file will be marked corrupted.  
   **解压/验证时不校验密码正确性**，错误密码会导致解密乱码，随后 CRC 检验失败，文件被标记为损坏。

2. **RS repair requires the first volume (or the single-file archive) to be specified.**  
   All volumes are automatically discovered by incrementing the volume number.  
   **RS 修复时需指定第一个分卷**，程序会自动递增编号读取后续分卷。

3. **`--rs` must be specified at archive creation time.**  
   Repair is not possible without parity blocks.  
   **`--rs` 必须在创建归档时指定**，没有校验块则无法修复。

4. **Section size affects recovery granularity and archive overhead.**  
   Smaller sections = finer recovery + more header overhead.  
   **section 大小影响恢复粒度和元数据开销**，越小越精细但开销越大。

5. **In-archive paths always use forward slashes (`/`)**, regardless of the host OS.  
   When extracting specific files, use forward slashes in the file list.  
   **归档内路径统一使用正斜杠 `/`**，提取指定文件时需使用正斜杠。

6. **The archive format is big-endian** for all numeric fields, making it portable across architectures.  
   **归档格式所有数值字段均为大端序**，具备跨架构可移植性。

