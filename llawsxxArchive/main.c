#define _CRT_SECURE_NO_WARNINGS
/*
 * lxar - LLawsXX ARchive format - Windows版本 (支持AES加密和ZSTD压缩)
 *
 *
 * 使用方法:
 *   lxar archive [-o <输出文件>] [-s <size>] [-p <password>] [-z <level>] <目录>        - 创建归档
 *   lxar extract [-o <输出目录>] [-p <password>] <归档文件>                 - 提取所有文件
 *   lxar extract [-o <输出目录>] [-p <password>] <归档> <文件列表>          - 提取指定文件
 *   lxar list <归档>                        - 列出归档内容
 *   lxar verify [-p <password>] <归档>                      - 验证归档完整性
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include "crc32.h"
#include "aes.h"
#include <windows.h>
#include <direct.h>
#include <zstd.h>  // 添加ZSTD头文件
#include <errno.h>

#define DEFAULT_SECTION_SIZE (256 * 1024)  // 默认256KB
#define MIN_SECTION_SIZE (1024)            // 最小1KB
#define MAX_SECTION_SIZE (64 * 1024 * 1024) // 最大64MB

#define MAGIC_NUMBER_FILE 0x424C4F43  // "BLOC" in ASCII
#define MAGIC_NUMBER_DIR 0x44495200   // "DIR\0" in ASCII
#define MAX_PATH_LEN 256
#define CRC32_SIZE 4

 // 标志位定义
#define FLAG_ENCRYPTED 0x01  // 数据已加密
#define FLAG_COMPRESSED 0x02  // 数据已压缩 (ZSTD)

// 默认压缩级别
#define DEFAULT_COMPRESSION_LEVEL 3

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;           // 4B Magic number (FILE or DIR)
    char filename[256];       // 256B Filename
    uint64_t mtime;           // 8B Modification time (UNIX timestamp)
    uint64_t total_size;      // 8B Total file size (0 for directories)
    uint64_t section_id;      // 8B Section ID (starts from 0)
    uint32_t section_size;    // 4B Section size (压缩后的数据大小，0 for directories)
    uint32_t original_size;   // 4B 原始数据大小 (压缩前，用于解压缩)
    uint64_t total_section_count;   // 8B total section count (0 for directories)
    uint64_t data_offset;     // 8B 数据在原文件中的偏移量
    uint32_t flags;           // 4B 标志位 (如: 0x01 = 加密, 0x02 = 压缩)
    uint32_t header_crc32;    // 4B header CRC32
    // Data follows immediately for files
    // Finally 4B CRC32 for files
} BlockHeader;
#pragma pack(pop)

typedef struct {
    char filename[256];
    uint64_t total_size;
    uint64_t actual_total_size;
    uint64_t section_count;
    uint64_t actual_section_count;
    uint64_t next_desired_section_id;
    uint64_t first_block_offset;
    int is_directory;          // 是否为目录
    int is_encrypted;          // 是否加密
    int is_compressed;         // 是否压缩
} FileInfo;

// 进度显示上下文结构体
typedef struct {
    uint64_t current;           // 当前处理的数据量
    uint64_t total;             // 总数据量
    uint64_t current_section;    // 当前处理的section编号
    uint64_t total_sections;     // 总的section数量
    const char* filename;        // 正在处理的文件名
    DWORD last_print_time;       // 上次打印时间
    uint64_t last_bytes;         // 上次打印时的字节数
    DWORD last_speed_time;       // 上次计算速度的时间
    uint64_t last_speed_bytes;   // 上次计算速度时的字节数
    uint64_t original_total;     // 原始总数据量（未压缩前）
    uint64_t compressed_total;   // 压缩后总数据量
    int initialized;             // 是否已初始化
    int printed;
} ProgressContext;

// 全局变量
int total_files_processed = 0;
int total_dirs_processed = 0;
FILE* g_archive = NULL;
uint32_t g_section_size = DEFAULT_SECTION_SIZE;  // 全局section size
uint8_t g_encryption_key[16] = { 0 };  // AES-128密钥
int g_encryption_enabled = 0;        // 是否启用加密
int g_compression_enabled = 1;        // 是否启用压缩（默认开启）
int g_compression_level = DEFAULT_COMPRESSION_LEVEL;  // 压缩级别
char g_output_path[MAX_PATH] = { 0 }; // 输出路径
// 添加全局变量来保存输入根路径
const char* g_input_root_path = NULL;
int g_error_count = 0;           // 错误计数
int g_warning_count = 0;         // 警告计数

// 初始化进度显示上下文
void progress_init(ProgressContext* ctx, uint64_t total, uint64_t total_sections, const char* filename) {
    ctx->current = 0;
    ctx->total = total;
    ctx->current_section = 0;
    ctx->total_sections = total_sections;
    ctx->filename = filename;
    ctx->last_print_time = GetTickCount();
    ctx->last_bytes = 0;
    ctx->last_speed_time = 0;
    ctx->last_speed_bytes = 0;
    ctx->original_total = 0;
    ctx->compressed_total = 0;
    ctx->initialized = 1;
    ctx->printed = 0;
}

void progress_update_compression(ProgressContext* ctx, uint64_t original_bytes, uint64_t compressed_bytes) {
    if (!ctx->initialized) return;
    ctx->original_total += original_bytes;
    ctx->compressed_total += compressed_bytes;
}

// 更新进度并决定是否打印
int progress_update(ProgressContext* ctx, uint64_t bytes_processed, uint64_t section_num, int force_print) {
    if (!ctx->initialized) return 0;
    ctx->current = bytes_processed;
    ctx->current_section = section_num;

    DWORD current_time = GetTickCount();
    const DWORD print_interval_ms = 500; // 500毫秒 = 每秒2次

    if (current_time - ctx->last_print_time >= print_interval_ms || force_print) {
        // 计算进度百分比
        int percent = (ctx->total > 0) ? (int)((ctx->current * 100) / ctx->total) : 0;

        // 计算处理速度 (KB/s)
        double speed = 0.0;
        if (ctx->last_speed_time > 0) {
            DWORD time_diff = current_time - ctx->last_speed_time;
            if (time_diff > 0) {
                uint64_t bytes_diff = ctx->current - ctx->last_speed_bytes;
                speed = (bytes_diff / 1024.0) / (time_diff / 1000.0); // KB/s
            }
        }

        // 计算压缩率
        double compression_ratio = 0.0;
        if (ctx->original_total > 0) {
            compression_ratio = ((double)ctx->compressed_total / ctx->original_total) * 100.0;
        }

        // 打印进度信息
        if (ctx->total > 0) {
            if (ctx->original_total > 0) {
                // 显示压缩率
                printf("\rProgress: %llu MB / %llu MB (%d%%) | Speed: %.2f KB/s | Section id: %llu/%llu | Compression: %.1f%% (%llu -> %llu)   ",
                    ctx->current / (1024 * 1024),
                    ctx->total / (1024 * 1024),
                    percent,
                    speed,
                    (unsigned long long)ctx->current_section,
                    (unsigned long long)ctx->total_sections,
                    compression_ratio,
                    (unsigned long long)ctx->original_total,
                    (unsigned long long)ctx->compressed_total);
            }
            else {
                // 没有压缩率数据
                printf("\rProgress: %llu MB / %llu MB (%d%%) | Speed: %.2f KB/s | Section id: %llu/%llu   ",
                    ctx->current / (1024 * 1024),
                    ctx->total / (1024 * 1024),
                    percent,
                    speed,
                    (unsigned long long)ctx->current_section,
                    (unsigned long long)ctx->total_sections);
            }
        }
        else {
            // 对于总大小为0的文件（空文件），只显示section进度
            printf("\rProgress: Section: %llu/%llu | Speed: %.2f KB/s   ",
                (unsigned long long)ctx->current_section,
                (unsigned long long)ctx->total_sections,
                speed);
        }
        ctx->printed = 1;
        ctx->last_print_time = current_time;
        ctx->last_speed_bytes = ctx->current;
        ctx->last_speed_time = current_time;

        return 1; // 表示打印了进度
    }

    return 0; // 未打印进度
}

// 进度显示结束，打印换行
void progress_finish(ProgressContext* ctx) {
    if (ctx->printed) {
        progress_update(ctx, ctx->total, ctx->total_sections - 1, 1);
        printf("\n");
        // 显示最终压缩率
        if (ctx->original_total > 0 && ctx->compressed_total > 0) {
            double compression_ratio = ((double)ctx->compressed_total / ctx->original_total) * 100.0;
            double saved_space = 100.0 - compression_ratio;
            printf("  Final compression: %.1f%% of original (%.1f%% space saved) - %llu -> %llu bytes\n",
                compression_ratio, saved_space,
                (unsigned long long)ctx->original_total,
                (unsigned long long)ctx->compressed_total);
        }
    }
    ctx->initialized = 0;
}

// 大小端转换函数
uint16_t htobe16(uint16_t x) {
#if defined(_MSC_VER) && (_MSC_VER >= 1900) || defined(__MINGW32__)
    return _byteswap_ushort(x);
#else
    return (x >> 8) | (x << 8);
#endif
}

uint16_t be16toh(uint16_t x) {
    return htobe16(x);
}

uint32_t htobe32(uint32_t x) {
#if defined(_MSC_VER) && (_MSC_VER >= 1900) || defined(__MINGW32__)
    return _byteswap_ulong(x);
#else
    return ((x & 0xFF000000) >> 24) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x000000FF) << 24);
#endif
}

uint32_t be32toh(uint32_t x) {
    return htobe32(x);
}

uint64_t htobe64(uint64_t x) {
#if defined(_MSC_VER) && (_MSC_VER >= 1900) || defined(__MINGW32__)
    return _byteswap_uint64(x);
#else
    return ((x & 0xFF00000000000000ULL) >> 56) |
        ((x & 0x00FF000000000000ULL) >> 40) |
        ((x & 0x0000FF0000000000ULL) >> 24) |
        ((x & 0x000000FF00000000ULL) >> 8) |
        ((x & 0x00000000FF000000ULL) << 8) |
        ((x & 0x0000000000FF0000ULL) << 24) |
        ((x & 0x000000000000FF00ULL) << 40) |
        ((x & 0x00000000000000FFULL) << 56);
#endif
}

uint64_t be64toh(uint64_t x) {
    return htobe64(x);
}

// 将主机字节序的BlockHeader转换为大端字节序（用于写入）
void header_host_to_be(const BlockHeader* host, BlockHeader* be) {
    be->magic = htobe32(host->magic);
    memcpy(be->filename, host->filename, 256);
    be->mtime = htobe64(host->mtime);
    be->total_size = htobe64(host->total_size);
    be->section_id = htobe64(host->section_id);
    be->section_size = htobe32(host->section_size);
    be->total_section_count = htobe64(host->total_section_count);
    be->data_offset = htobe64(host->data_offset);
    be->flags = htobe32(host->flags);
    be->header_crc32 = htobe32(host->header_crc32);
    be->original_size = htobe32(host->original_size);
}

// 将大端字节序的BlockHeader转换为主机字节序（用于读取）
void header_be_to_host(const BlockHeader* be, BlockHeader* host) {
    host->magic = be32toh(be->magic);
    memcpy(host->filename, be->filename, 256);
    host->mtime = be64toh(be->mtime);
    host->total_size = be64toh(be->total_size);
    host->section_id = be64toh(be->section_id);
    host->section_size = be32toh(be->section_size);
    host->total_section_count = be64toh(be->total_section_count);
    host->data_offset = be64toh(be->data_offset);
    host->flags = be32toh(be->flags);
    host->header_crc32 = be32toh(be->header_crc32);
    host->original_size = be32toh(be->original_size);
}

// 写入CRC32（自动转换字节序）
size_t write_crc32(FILE* file, uint32_t crc) {
    uint32_t crc_be = htobe32(crc);
    return fwrite(&crc_be, sizeof(uint32_t), 1, file);
}

// 读取CRC32（自动转换字节序）
int read_crc32(FILE* file, uint32_t* crc) {
    *crc = 0;
    uint32_t crc_be;
    size_t read = fread(&crc_be, sizeof(uint32_t), 1, file);
    if (read != 1) return 0;
    *crc = be32toh(crc_be);
    return 1;
}

// 写入整个BlockHeader（自动转换字节序）
size_t write_block_header(FILE* file, BlockHeader* header) {
    BlockHeader be_header;
    header_host_to_be(header, &be_header);
    uint32_t crc = crc32_calc(&be_header, sizeof(BlockHeader) - 4);
    be_header.header_crc32 = htobe32(crc);
    header->header_crc32 = crc;
    return fwrite(&be_header, sizeof(BlockHeader), 1, file);
}

// 读取整个BlockHeader（自动转换字节序）
int read_block_header(FILE* file, BlockHeader* header) {
    BlockHeader be_header;
    size_t read = fread(&be_header, sizeof(BlockHeader), 1, file);
    if (read != 1) return 0;
    // 计算header CRC时不包括header_crc32字段
    uint32_t calc_header_crc32 = crc32_calc(&be_header, sizeof(BlockHeader) - 4);
    uint32_t crc = be32toh(be_header.header_crc32);
    if (crc != calc_header_crc32) {
        printf("Error: Header crc32 mismatch (stored: 0x%08x calc: 0x%08x)\n",
            crc, calc_header_crc32);
        return 0;
    }
    header_be_to_host(&be_header, header);
    return 1;
}

// 将16进制字符串转换为字节数组
int hex_to_bytes(const char* hex, uint8_t* bytes, size_t max_bytes) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;

    if (byte_len > max_bytes) byte_len = max_bytes;

    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    // 如果密码不足16字节，剩余部分填充0
    if (byte_len < 16) {
        memset(bytes + byte_len, 0, 16 - byte_len);
    }

    return 0;
}

// 从密码生成密钥
void generate_key_from_password(const char* password) {
    if (!password || strlen(password) == 0) {
        g_encryption_enabled = 0;
        return;
    }

    printf("Original password: %s\n", password);

    // 如果密码是16进制格式（32个字符）
    if (strlen(password) == 32) {
        hex_to_bytes(password, g_encryption_key, 16);
        printf("Password is 32-character hex string, converted to 16-byte key\n");
    }
    else {
        // 否则使用密码的MD5或简单哈希作为密钥
        size_t len = strlen(password);
        if (len > 16) len = 16;
        memcpy(g_encryption_key, password, len);
        if (len < 16) {
            memset(g_encryption_key + len, 0, 16 - len);
        }
        printf("Password is regular string, converted to 16-byte key\n");
    }

    // 打印生成的16字节密钥
    printf("Generated AES-128 key (16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", g_encryption_key[i]);
    }
    printf("\n");

    g_encryption_enabled = 1;
    printf("Encryption enabled (AES-128 CBC)\n");
}

// 从header_crc32生成IV
void generate_iv_from_crc(uint32_t crc, uint8_t* iv) {
    // 将crc重复4次作为IV
    for (int i = 0; i < 4; i++) {
        iv[i * 4] = (crc >> 24) & 0xFF;
        iv[i * 4 + 1] = (crc >> 16) & 0xFF;
        iv[i * 4 + 2] = (crc >> 8) & 0xFF;
        iv[i * 4 + 3] = crc & 0xFF;
    }
}

uint32_t get_pad_len(uint32_t data_len) {
    uint32_t padding = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    if (padding == 0) padding = AES_BLOCK_SIZE;
    return padding;
}

int pkcs7_unpad(uint8_t* data, uint32_t padded_len, uint32_t* original_len) {
    if (padded_len == 0 || padded_len % AES_BLOCK_SIZE != 0) {
        return -1;
    }

    uint8_t padding_value = data[padded_len - 1];
    if (padding_value == 0 || padding_value > AES_BLOCK_SIZE) {
        return -1;
    }

    // 验证所有填充字节
    for (uint32_t i = padded_len - padding_value; i < padded_len; i++) {
        if (data[i] != padding_value) {
            return -1;
        }
    }

    *original_len = padded_len - padding_value;
    return 0;
}

void pkcs7_pad(uint8_t* data, uint32_t data_len, uint32_t padding) {
    for (uint32_t i = 0; i < padding; i++) {
        data[data_len + i] = (uint8_t)padding;
    }
}

// 加密/解密数据块
void process_data_block(uint8_t* data, uint32_t data_len, uint32_t header_crc, int encrypt) {
    if (!g_encryption_enabled) return;

    uint8_t iv[16];
    generate_iv_from_crc(header_crc, iv);

    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 };

    aes_key_setup(g_encryption_key, key_schedule, AES_KEY_SIZE);
    if (encrypt) {
        aes_encrypt_cbc_inplace(data, data_len, key_schedule, AES_KEY_SIZE, iv);
    }
    else {
        aes_decrypt_cbc_inplace(data, data_len, key_schedule, AES_KEY_SIZE, iv);
    }
}

// ZSTD压缩函数
uint8_t* compress_zstd(const uint8_t* data, size_t data_len, size_t* compressed_len, int level) {
    // 获取最大压缩后大小
    size_t max_compressed_size = ZSTD_compressBound(data_len);
    uint8_t* compressed = (uint8_t*)malloc(max_compressed_size);
    if (!compressed) {
        printf("Error: Failed to allocate compression buffer\n");
        return NULL;
    }

    // 执行压缩
    *compressed_len = ZSTD_compress(compressed, max_compressed_size, data, data_len, level);

    if (ZSTD_isError(*compressed_len)) {
        printf("Error: ZSTD compression failed: %s\n", ZSTD_getErrorName(*compressed_len));
        free(compressed);
        return NULL;
    }

    return compressed;
}

// ZSTD解压缩函数
uint8_t* decompress_zstd(const uint8_t* compressed_data, size_t compressed_len, size_t original_len) {
    uint8_t* decompressed = (uint8_t*)malloc(original_len);
    if (!decompressed) {
        printf("Error: Failed to allocate decompression buffer\n");
        return NULL;
    }

    size_t result = ZSTD_decompress(decompressed, original_len, compressed_data, compressed_len);

    if (ZSTD_isError(result)) {
        printf("Error: ZSTD decompression failed: %s\n", ZSTD_getErrorName(result));
        free(decompressed);
        return NULL;
    }

    if (result != original_len) {
        printf("Error: Decompressed size mismatch: expected %zu, got %zu\n", original_len, result);
        free(decompressed);
        return NULL;
    }

    return decompressed;
}

char* dirname(char* path) {
    static char result[MAX_PATH];
    if (!path || strlen(path) == 0) {
        strcpy(result, ".");
        return result;
    }

    char* last_slash = strrchr(path, '\\');
    char* last_slash2 = strrchr(path, '/');

    if (last_slash2 > last_slash) last_slash = last_slash2;

    if (last_slash) {
        size_t len = last_slash - path;
        if (len == 0) {
            strcpy(result, "\\");
        }
        else {
            strncpy(result, path, len);
            result[len] = '\0';
        }
    }
    else {
        strcpy(result, ".");
    }
    return result;
}

// 获取路径的最后一个部分（文件名或目录名）
const char* get_last_path_component(const char* path) {
    const char* last_slash = strrchr(path, '\\');
    const char* last_slash2 = strrchr(path, '/');

    if (last_slash2 > last_slash) last_slash = last_slash2;

    if (last_slash) {
        return last_slash + 1;
    }
    return path;
}

// 获取文件相对于根目录的路径
int get_relative_path(const char* full_path, const char* root_path, char* relative_path, size_t max_len) {
    // 规范化路径分隔符为反斜杠（Windows风格）
    char norm_full[MAX_PATH];
    char norm_root[MAX_PATH];

    strncpy(norm_full, full_path, MAX_PATH - 1);
    strncpy(norm_root, root_path, MAX_PATH - 1);
    norm_full[MAX_PATH - 1] = '\0';
    norm_root[MAX_PATH - 1] = '\0';

    // 将所有正斜杠转换为反斜杠
    for (int i = 0; norm_full[i]; i++) {
        if (norm_full[i] == '/') norm_full[i] = '\\';
    }
    for (int i = 0; norm_root[i]; i++) {
        if (norm_root[i] == '/') norm_root[i] = '\\';
    }

    // 去除根路径末尾的斜杠
    size_t root_len = strlen(norm_root);
    while (root_len > 0 && (norm_root[root_len - 1] == '\\' || norm_root[root_len - 1] == '/')) {
        norm_root[--root_len] = '\0';
    }

    // 检查full_path是否以root_path开头
    if (_strnicmp(norm_full, norm_root, root_len) != 0) {
        // 对于SMB路径或其他网络路径的特殊处理
        char* root_colon = strchr(norm_root, ':');
        char* full_colon = strchr(norm_full, ':');

        if (root_colon && full_colon) {
            // 比较盘符之后的部分
            if (_stricmp(root_colon + 1, full_colon + 1) == 0) {
                // 盘符相同，使用完整路径作为相对路径
                strncpy(relative_path, norm_full + (full_colon - norm_full + 1), max_len - 1);
                relative_path[max_len - 1] = '\0';

                // 移除开头的斜杠
                while (*relative_path == '\\' || *relative_path == '/') {
                    memmove(relative_path, relative_path + 1, strlen(relative_path));
                }
                return 0;
            }
        }

        printf("Warning: Path '%s' is not under root '%s'\n", full_path, root_path);
        // 返回完整路径（去掉盘符）
        if (full_colon) {
            strncpy(relative_path, full_colon + 1, max_len - 1);
            relative_path[max_len - 1] = '\0';
            while (*relative_path == '\\' || *relative_path == '/') {
                memmove(relative_path, relative_path + 1, strlen(relative_path));
            }
        }
        else {
            strncpy(relative_path, norm_full, max_len - 1);
        }
        return -1;
    }

    // 获取相对路径
    const char* rel_start = norm_full + root_len;
    while (*rel_start == '\\' || *rel_start == '/') {
        rel_start++;
    }

    strncpy(relative_path, rel_start, max_len - 1);
    relative_path[max_len - 1] = '\0';

    // 将反斜杠转换为正斜杠（归档内使用正斜杠保持跨平台兼容）
    for (int i = 0; relative_path[i]; i++) {
        if (relative_path[i] == '\\') relative_path[i] = '/';
    }

    return 0;
}

long long get_file_size(const char* filename) {
    struct __stat64 st;
    long long filesize = 0;
    if (_stat64(filename, &st) == 0) {
        filesize = st.st_size;
    }
    return filesize;
}

// 检查路径是否为目录
int is_directory(const char* path) {
    struct __stat64 st;
    if (_stat64(path, &st) == 0) {
        return (st.st_mode & _S_IFDIR) != 0;
    }
    return 0;
}

// 解析size参数（支持K、M、G后缀）
uint32_t parse_size(const char* size_str) {
    char* endptr;
    unsigned long long size = strtoull(size_str, &endptr, 10);

    if (endptr && *endptr) {
        switch (*endptr) {
        case 'K':
        case 'k':
            size *= 1024;
            break;
        case 'M':
        case 'm':
            size *= 1024 * 1024;
            break;
        case 'G':
        case 'g':
            size *= 1024 * 1024 * 1024;
            break;
        default:
            printf("Warning: Unknown size suffix '%c', using as bytes\n", *endptr);
            break;
        }
    }

    // 检查范围
    if (size < MIN_SECTION_SIZE) {
        printf("Warning: Section size too small (%llu bytes), using minimum %d bytes\n",
            size, MIN_SECTION_SIZE);
        size = MIN_SECTION_SIZE;
    }
    else if (size > MAX_SECTION_SIZE) {
        printf("Warning: Section size too large (%llu bytes), using maximum %d bytes\n",
            size, MAX_SECTION_SIZE);
        size = MAX_SECTION_SIZE;
    }

    return (uint32_t)size;
}

// 解析压缩级别参数
int parse_compression_level(const char* level_str) {
    char* endptr;
    long level = strtol(level_str, &endptr, 10);

    if (endptr == level_str || *endptr != '\0') {
        printf("Warning: Invalid compression level '%s', using default %d\n",
            level_str, DEFAULT_COMPRESSION_LEVEL);
        return DEFAULT_COMPRESSION_LEVEL;
    }
    if (level == 0) return level;

    // ZSTD压缩级别范围通常是1-22
    if (level < 1 || level > 22) {
        printf("Warning: Compression level %ld out of range (1-22), using default %d\n",
            level, DEFAULT_COMPRESSION_LEVEL);
        return DEFAULT_COMPRESSION_LEVEL;
    }

    return (int)level;
}

// 将Unix时间戳转换为可读的日期时间字符串
void format_datetime(uint64_t timestamp, char* buffer, size_t buffer_size) {
    time_t t = (time_t)timestamp;
    struct tm* tm_info = localtime(&t);
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Windows下遍历目录的函数
void walk_directory(const char* path, void (*file_callback)(const char*), void (*dir_callback)(const char*)) {
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", path);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search_path, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open directory %s (error: %lu)\n", path, GetLastError());
        g_error_count++;
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 &&
            strcmp(findData.cFileName, "..") != 0) {

            char full_path[MAX_PATH];
            snprintf(full_path, MAX_PATH, "%s\\%s", path, findData.cFileName);

            // 检查路径长度
            if (strlen(full_path) >= MAX_PATH) {
                printf("Error: Path too long %s\n", full_path);
                g_error_count++;
                break;
            }

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // 先处理目录本身
                if (dir_callback) {
                    dir_callback(full_path);
                }
                // 然后递归遍历子目录
                walk_directory(full_path, file_callback, dir_callback);
            }
            else {
                if (file_callback) {
                    file_callback(full_path);
                }
            }
        }
    } while (FindNextFileA(hFind, &findData));

    DWORD error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        printf("Error: Error while enumerating directory %s (error: %lu)\n", path, error);
        g_error_count++;
    }
    FindClose(hFind);
}

// Windows下创建目录（支持指定根路径）
int create_directories_with_root(const char* root_path, const char* rel_path) {
    char full_path[MAX_PATH];

    if (root_path && strlen(root_path) > 0) {
        // 规范化根路径
        char norm_root[MAX_PATH];
        strncpy(norm_root, root_path, MAX_PATH - 1);
        norm_root[MAX_PATH - 1] = '\0';

        // 去除根路径末尾的斜杠
        size_t root_len = strlen(norm_root);
        while (root_len > 0 && (norm_root[root_len - 1] == '\\' || norm_root[root_len - 1] == '/')) {
            norm_root[--root_len] = '\0';
        }

        // 构建完整路径
        snprintf(full_path, MAX_PATH, "%s\\%s", norm_root, rel_path);
    }
    else {
        strncpy(full_path, rel_path, MAX_PATH - 1);
        full_path[MAX_PATH - 1] = '\0';
    }

    // 将正斜杠转换为反斜杠（Windows）
    for (int i = 0; full_path[i]; i++) {
        if (full_path[i] == '/') full_path[i] = '\\';
    }

    // 创建目录
    char tmp[MAX_PATH];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", full_path);
    len = strlen(tmp);
    if (tmp[len - 1] == '\\') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '\\') {
            *p = 0;
            _mkdir(tmp);
            *p = '\\';
        }
    }
    return _mkdir(tmp);
}

// 创建目录（兼容旧代码）
int create_directories(const char* path) {
    return create_directories_with_root(NULL, path);
}

// 构建输出文件路径
void build_output_path(const char* output_root, const char* rel_path, char* out_path, size_t max_len) {
    if (output_root && strlen(output_root) > 0) {
        // 规范化输出根路径
        char norm_root[MAX_PATH];
        strncpy(norm_root, output_root, MAX_PATH - 1);
        norm_root[MAX_PATH - 1] = '\0';

        // 去除根路径末尾的斜杠
        size_t root_len = strlen(norm_root);
        while (root_len > 0 && (norm_root[root_len - 1] == '\\' || norm_root[root_len - 1] == '/')) {
            norm_root[--root_len] = '\0';
        }

        // 构建完整路径
        snprintf(out_path, max_len, "%s\\%s", norm_root, rel_path);
    }
    else {
        strncpy(out_path, rel_path, max_len - 1);
        out_path[max_len - 1] = '\0';
    }

    // 将正斜杠转换为反斜杠（Windows）
    for (int i = 0; out_path[i]; i++) {
        if (out_path[i] == '/') out_path[i] = '\\';
    }
}

// 验证块头的有效性
int validate_block_header(BlockHeader* header, long long found_pos, long long start_pos, uint64_t* block_num) {
    if (header->magic != MAGIC_NUMBER_FILE && header->magic != MAGIC_NUMBER_DIR) {
        printf("Error: Invalid magic number 0x%08x at position %llu\n",
            header->magic, (unsigned long long)_ftelli64(g_archive) - sizeof(BlockHeader));
        return -1;
    }

    if (start_pos != found_pos) {
        printf("Block %llu: Start position not equal to found position (start: 0x%llx found: 0x%llx)\n",
            (unsigned long long)(block_num ? *block_num : 0),
            (unsigned long long)start_pos, (unsigned long long)found_pos);
    }

    // 验证data_offset是否合理
    if (header->magic == MAGIC_NUMBER_FILE && header->section_size > 0) {
        if (header->data_offset > header->total_size) {
            printf("Warning: Block %llu data_offset %llu exceeds total_size %llu\n",
                (unsigned long long)(block_num ? *block_num : 0),
                (unsigned long long)header->data_offset,
                (unsigned long long)header->total_size);
        }
    }

    if (block_num) (*block_num)++;

    return 0;
}

// 扫描并定位下一个magic number
long long find_next_magic(FILE* archive, long long start_pos, long long file_size) {
    unsigned char byte;
    long long pos = start_pos;
    uint32_t magic_accumulator = 0;

    if (start_pos >= file_size - 4) {
        return -1;
    }

    _fseeki64(archive, pos, SEEK_SET);

    while (fread(&byte, 1, 1, archive) == 1) {
        magic_accumulator = ((magic_accumulator << 8) & 0xFFFFFF00) | byte;

        if (magic_accumulator == MAGIC_NUMBER_FILE || magic_accumulator == MAGIC_NUMBER_DIR) {
            long long found_pos = pos - 3;
            _fseeki64(archive, found_pos, SEEK_SET);
            return found_pos;
        }

        pos++;
    }

    return -1;
}

// 处理目录的回调函数
void process_directory(const char* dirpath) {
    // 获取相对于输入根目录的路径
    char relative_path[256] = { 0 };

    if (get_relative_path(dirpath, g_input_root_path, relative_path, sizeof(relative_path)) != 0) {
        printf("Warning: Path issue for directory %s\n", dirpath);
        g_warning_count++;
        // 继续处理
    }

    // 确保目录名以/结尾
    size_t len = strlen(relative_path);
    if (len > 0 && relative_path[len - 1] != '/') {
        if (len < 255) {
            relative_path[len] = '/';
            relative_path[len + 1] = '\0';
        }
    }
    relative_path[255] = '\0';

    // 获取目录信息
    struct __stat64 st;
    if (_stat64(dirpath, &st) != 0) {
        printf("Error: Cannot get directory stat %s\n", dirpath);
        g_error_count++;
        return;
    }

    printf("Archiving directory: %s\n", relative_path);

    // 创建目录块
    BlockHeader header = { 0 };
    header.magic = MAGIC_NUMBER_DIR;
    strncpy(header.filename, relative_path, 255);
    header.filename[255] = '\0';
    header.mtime = st.st_mtime;
    header.total_size = 0;
    header.section_id = 0;
    header.section_size = 0;
    header.total_section_count = 0;
    header.data_offset = 0;
    header.flags = 0;
    header.original_size = 0;

    // 使用封装函数写入（自动转换字节序）
    if (write_block_header(g_archive, &header) != 1) {
        printf("Error: Failed to write directory header for %s\n", relative_path);
        g_error_count++;
        return;
    }

    // 目录没有数据块，直接写入CRC32（全0）
    if (write_crc32(g_archive, 0) != 1) {
        printf("Error: Failed to write CRC for directory %s\n", relative_path);
        g_error_count++;
        return;
    }

    total_dirs_processed++;
}

// 处理单个文件的回调函数
void process_file(const char* filepath) {
    FILE* infile = fopen(filepath, "rb");
    if (!infile) {
        printf("Error: Cannot open file %s\n", filepath);
        g_error_count++;
        return;
    }

    // 获取文件信息
    struct __stat64 st;
    if (_stat64(filepath, &st) != 0) {
        printf("Error: Cannot get file stat %s\n", filepath);
        fclose(infile);
        g_error_count++;
        return;
    }

    // 获取相对于输入根目录的路径
    char relative_path[256] = { 0 };
    if (get_relative_path(filepath, g_input_root_path, relative_path, sizeof(relative_path)) != 0) {
        printf("Warning: Path issue for %s\n", filepath);
        g_warning_count++;
        // 继续处理，使用可能不完整的路径
    }
    relative_path[255] = '\0';

    long long file_size = st.st_size;

    if (file_size == 0) {
        // 处理0字节文件
        printf("Archiving empty file: %s\n", relative_path);

        BlockHeader header = { 0 };
        header.magic = MAGIC_NUMBER_FILE;
        strncpy(header.filename, relative_path, 255);
        header.filename[255] = '\0';
        header.mtime = st.st_mtime;
        header.total_size = 0;
        header.section_id = 0;
        header.section_size = 0;
        header.total_section_count = 0;
        header.flags = 0;
        if (g_encryption_enabled) header.flags |= FLAG_ENCRYPTED;
        if (g_compression_enabled) header.flags |= FLAG_COMPRESSED;
        header.data_offset = 0;
        header.original_size = 0;

        // 使用封装函数写入（自动转换字节序）
        if (write_block_header(g_archive, &header) != 1) {
            printf("Error: Failed to write file header for %s\n", relative_path);
            fclose(infile);
            g_error_count++;
            return;
        }

        // 空文件没有数据，直接写入CRC32（全0）
        if (write_crc32(g_archive, 0) != 1) {
            printf("Error: Failed to write CRC for empty file %s\n", relative_path);
            fclose(infile);
            g_error_count++;
            return;
        }

        total_files_processed++;
    }
    else {
        // 处理非空文件
        uint64_t remaining = file_size;
        uint64_t total_section_count = (file_size + g_section_size - 1) / g_section_size;
        uint64_t section_id = 0;
        uint64_t total_write = 0;
        uint64_t file_offset = 0;
        int file_error = 0;

        ProgressContext progress;
        progress_init(&progress, file_size, total_section_count, relative_path);

        printf("Archiving: %s (size: %llu bytes, sections: %llu, section size: %u bytes%s%s)\n",
            relative_path, (unsigned long long)file_size,
            (unsigned long long)total_section_count, g_section_size,
            g_encryption_enabled ? ", encrypted" : "",
            g_compression_enabled ? ", compressed (ZSTD)" : "");

        while (remaining > 0)
        {
            uint32_t section_size = (remaining > g_section_size) ? g_section_size : (uint32_t)remaining;

            // 读取原始数据
            uint8_t* original_buffer = (uint8_t*)malloc(section_size);
            if (!original_buffer) {
                printf("Error: Out of memory for %s\n", relative_path);
                fclose(infile);
                g_error_count++;
                return;
            }

            size_t actual_read = fread(original_buffer, 1, section_size, infile);
            if (section_size - actual_read > 0) {
                printf("Error: Short read for %s (expected %u bytes, got %zu)\n",
                    relative_path, section_size, actual_read);
                free(original_buffer);
                fclose(infile);
                g_error_count++;
                return;
            }

            uint8_t* data_to_write = original_buffer;
            uint32_t data_to_write_len = section_size;
            uint32_t original_len = section_size;
            uint32_t compressed_len = 0;

            // 压缩数据（如果启用压缩）
            if (g_compression_enabled) {
                size_t zstd_compressed_len;
                uint8_t* compressed_data = compress_zstd(original_buffer, section_size,
                    &zstd_compressed_len, g_compression_level);

                if (compressed_data) {
                    // 只有在压缩后确实变小了才使用压缩数据
                    if (zstd_compressed_len < section_size) {
                        data_to_write = compressed_data;
                        data_to_write_len = (uint32_t)zstd_compressed_len;
                        compressed_len = (uint32_t)zstd_compressed_len;

                        // 更新压缩率信息
                        progress_update_compression(&progress, section_size, (uint32_t)zstd_compressed_len);

                        free(original_buffer);  // 释放原始缓冲区
                    }
                    else {
                        // 压缩后没有变小，使用原始数据
                        free(compressed_data);
                        // 更新压缩率信息（未压缩，比例为1:1）
                        progress_update_compression(&progress, section_size, section_size);
                        //printf("Debug: Section %llu compression ratio not beneficial, using original (zstd_compressed_len %lld section_size %u)\n",
                        //    (unsigned long long)section_id, zstd_compressed_len, section_size);
                    }
                }
            }
            else {
                // 压缩未启用，更新压缩率信息（比例为1:1）
                progress_update_compression(&progress, section_size, section_size);
            }

            // 如果需要加密
            uint32_t pad_len = 0;
            if (g_encryption_enabled) {
                pad_len = get_pad_len(data_to_write_len);
                uint8_t* padded_buffer = (uint8_t*)realloc(data_to_write, data_to_write_len + pad_len);
                if (!padded_buffer) {
                    printf("Error: Failed to allocate padding buffer\n");
                    free(data_to_write);
                    fclose(infile);
                    g_error_count++;
                    return;
                }
                data_to_write = padded_buffer;
                pkcs7_pad(data_to_write, data_to_write_len, pad_len);
                data_to_write_len += pad_len;
            }

            BlockHeader header = { 0 };
            header.magic = MAGIC_NUMBER_FILE;
            strncpy(header.filename, relative_path, 255);
            header.filename[255] = '\0';
            header.mtime = st.st_mtime;
            header.total_size = file_size;
            header.section_id = section_id;
            header.section_size = data_to_write_len;  // 加密后的数据大小（如果有加密）
            header.total_section_count = total_section_count;
            header.flags = 0;
            if (g_encryption_enabled) header.flags |= FLAG_ENCRYPTED;
            if (g_compression_enabled && compressed_len > 0) header.flags |= FLAG_COMPRESSED;
            header.data_offset = file_offset;
            header.original_size = original_len;  // 保存原始大小用于解压缩

            // 写入块头
            if (write_block_header(g_archive, &header) != 1) {
                printf("Error: Failed to write file header for %s section id %llu\n",
                    relative_path, (unsigned long long)section_id);
                free(data_to_write);
                fclose(infile);
                g_error_count++;
                return;
            }

            // 计算CRC32（数据写入前）
            CRC32_Context ctx;
            crc32_init(&ctx);

            // 如果需要加密，在这里执行加密（必须在CRC计算之前）
            if (g_encryption_enabled) {
                process_data_block(data_to_write, data_to_write_len, header.header_crc32, 1);
            }

            // 更新CRC（加密后的数据）
            crc32_update(&ctx, data_to_write, data_to_write_len);

            // 写入数据
            if (fwrite(data_to_write, 1, data_to_write_len, g_archive) != data_to_write_len) {
                printf("Error: Failed to write data for %s section id %llu\n",
                    relative_path, (unsigned long long)section_id);
                free(data_to_write);
                fclose(infile);
                g_error_count++;
                return;
            }

            uint32_t crc = crc32_final(&ctx);

            // 写入CRC32
            if (write_crc32(g_archive, crc) != 1) {
                printf("Error: Failed to write CRC for %s section id %llu\n",
                    relative_path, (unsigned long long)section_id);
                free(data_to_write);
                fclose(infile);
                g_error_count++;
                return;
            }

            // 清理
            free(data_to_write);

            remaining -= section_size;
            total_write += section_size;
            file_offset += section_size;

            progress_update(&progress, total_write, section_id, 0);

            section_id++;
        }

        total_files_processed++;
        progress_finish(&progress);

        if (file_error) {
            printf("Warning: File %s had errors during archiving\n", relative_path);
            g_warning_count++;
        }
    }

    fclose(infile);
}

// 创建归档文件
int create_archive(const char* archive_name, const char* input_path) {
    // 检查输入路径是否存在
    if (!is_directory(input_path)) {
        printf("Error: Input path does not exist: %s\n", input_path);
        return -1;
    }

    g_archive = fopen(archive_name, "wb");
    if (!g_archive) {
        printf("Error: Cannot create archive file: %s\n", archive_name);
        return -1;
    }

    // 重置计数器和错误标志
    total_files_processed = 0;
    total_dirs_processed = 0;
    g_error_count = 0;
    g_warning_count = 0;

    // 保存输入根路径供回调函数使用
    static char input_root[MAX_PATH];
    strncpy(input_root, input_path, MAX_PATH - 1);
    input_root[MAX_PATH - 1] = '\0';
    // 去除末尾的斜杠
    size_t root_len = strlen(input_root);
    while (root_len > 0 && (input_root[root_len - 1] == '\\' || input_root[root_len - 1] == '/')) {
        input_root[--root_len] = '\0';
    }
    g_input_root_path = input_root;

    printf("Creating archive: %s\n", archive_name);
    printf("Input path: %s\n", input_path);
    printf("Section size: %u bytes (%.2f KB, %.2f MB)\n",
        g_section_size,
        g_section_size / 1024.0,
        g_section_size / (1024.0 * 1024.0));
    if (g_encryption_enabled) {
        printf("Encryption: AES-128 CBC enabled\n");
    }
    if (g_compression_enabled) {
        printf("Compression: ZSTD level %d enabled\n", g_compression_level);
    }

    // Windows下使用自定义目录遍历，先处理目录，再处理文件
    walk_directory(input_path, process_file, process_directory);

    fclose(g_archive);

    // 输出最终统计
    printf("\nArchive creation completed:\n");
    printf("  - Directories: %d\n", total_dirs_processed);
    printf("  - Files: %d (including empty files)\n", total_files_processed);
    printf("  - Total: %d\n", total_files_processed + total_dirs_processed);

    if (g_warning_count > 0) {
        printf("  - Warnings: %d\n", g_warning_count);
    }

    if (g_error_count > 0) {
        printf("  - Errors: %d\n", g_error_count);
        printf("Archive created with errors! Some files may be missing or corrupted.\n");
        return -1;
    }
    else {
        printf("Archive created successfully: %s\n", archive_name);
        return 0;
    }
}

// 列出归档内容
int list_archive(const char* archive_name) {
    FILE* archive = fopen(archive_name, "rb");
    if (!archive) {
        printf("Cannot open archive file: %s\n", archive_name);
        return -1;
    }

    BlockHeader header;
    uint64_t total_files = 0;
    uint64_t total_dirs = 0;
    uint64_t total_blocks = 0;
    char current_file[256] = { 0 };
    long long start_pos = 0;
    long long pos = 0;
    int result;
    char datetime_str[20];

    // 用于跟踪哪些文件已经显示过
    typedef struct {
        char filename[256];
        int displayed;
        uint64_t total_size;
        uint64_t total_sections;
        uint64_t mtime;
        int is_encrypted;
        int is_compressed;
    } DisplayedFile;

    DisplayedFile* displayed_files = NULL;
    int displayed_count = 0;
    int displayed_capacity = 0;

    printf("Archive contents: %s\n", archive_name);
    printf("%-30s %-20s %-10s %-10s %-12s %s\n", "Name", "Modified Time", "Type", "Size", "Flags", "CRC");
    printf("------------------------------------------------\n");

    long long filesize = get_file_size(archive_name);

    while (1) {
        pos = find_next_magic(archive, start_pos, filesize);
        if (pos == -1) break;

        if (!read_block_header(archive, &header)) {
            // 头损坏的情况
            printf("%-30s %-20s %-10s %-10s %-12s %s\n",
                "[CORRUPTED BLOCK]", "", "ERROR", "", "", "HEADER CRC FAILED");
            start_pos = pos + 1;
            continue;
        }

        // 使用公共函数验证块头
        result = validate_block_header(&header, pos, start_pos, &total_blocks);
        if (result < 0) {
            start_pos = pos + 1;
            continue;
        }

        // 读取CRC32
        uint32_t stored_crc;

        if (header.magic == MAGIC_NUMBER_FILE && header.section_size > 0) {
            // 普通文件：跳过数据块后读CRC
            _fseeki64(archive, header.section_size, SEEK_CUR);
            read_crc32(archive, &stored_crc);
        }
        else {
            // 目录或空文件：直接读CRC（位于头之后）
            read_crc32(archive, &stored_crc);
        }

        // 格式化时间
        format_datetime(header.mtime, datetime_str, sizeof(datetime_str));

        // 构建标志字符串
        char flags_str[16] = "";
        if (header.flags & FLAG_ENCRYPTED) strcat(flags_str, "AES ");
        if (header.flags & FLAG_COMPRESSED) strcat(flags_str, "ZSTD");
        if (strlen(flags_str) == 0) strcpy(flags_str, "-");

        if (header.magic == MAGIC_NUMBER_DIR) {
            // 目录 - 总是显示
            printf("%-30s %-20s %-10s %-10s %-12s 0x%08x\n",
                header.filename, datetime_str, "<DIR>", "", flags_str, stored_crc);
            if (strcmp(current_file, header.filename) != 0) {
                total_dirs++;
                strcpy(current_file, header.filename);
            }
        }
        else {
            // 文件 - 检查是否已经显示过
            int already_displayed = 0;
            for (int i = 0; i < displayed_count; i++) {
                if (strcmp(displayed_files[i].filename, header.filename) == 0) {
                    already_displayed = 1;
                    break;
                }
            }

            if (!already_displayed) {
                // 新文件，添加到列表并显示
                if (displayed_count >= displayed_capacity) {
                    displayed_capacity = displayed_capacity ? displayed_capacity * 2 : 16;
                    displayed_files = (DisplayedFile*)realloc(displayed_files,
                        displayed_capacity * sizeof(DisplayedFile));
                    if (!displayed_files) {
                        printf("Error: Out of memory\n");
                        break;
                    }
                }

                strcpy(displayed_files[displayed_count].filename, header.filename);
                displayed_files[displayed_count].displayed = 1;
                displayed_files[displayed_count].total_size = header.total_size;
                displayed_files[displayed_count].total_sections = header.total_section_count;
                displayed_files[displayed_count].mtime = header.mtime;
                displayed_files[displayed_count].is_encrypted = (header.flags & FLAG_ENCRYPTED) ? 1 : 0;
                displayed_files[displayed_count].is_compressed = (header.flags & FLAG_COMPRESSED) ? 1 : 0;
                displayed_count++;

                // 显示文件信息（使用第一个找到的块的信息）
                printf("%-30s %-20s %-10s %-10llu %-12s 0x%08x",
                    header.filename, datetime_str, "FILE",
                    (unsigned long long)header.total_size,
                    flags_str, stored_crc);

                // 如果这不是第一个section，添加注释
                if (header.section_id != 0) {
                    printf(" (section id %llu of %llu - first block missing/corrupted?)",
                        (unsigned long long)header.section_id,
                        (unsigned long long)header.total_section_count);
                }
                printf("\n");
                total_files++;
            }
        }

        start_pos = _ftelli64(archive);
    }

    printf("------------------------------------------------\n");
    printf("Total: %llu directories, %llu files, %llu blocks\n",
        (unsigned long long)total_dirs,
        (unsigned long long)total_files,
        (unsigned long long)total_blocks);

    free(displayed_files);
    fclose(archive);
    return 0;
}

// 验证归档完整性
int verify_archive(const char* archive_name) {
    FILE* archive = fopen(archive_name, "rb");
    if (!archive) {
        printf("Cannot open archive file: %s\n", archive_name);
        return -1;
    }

    BlockHeader header;
    uint64_t block_num = 0;
    int corrupted_blocks = 0;
    int missing_first_blocks = 0;
    long long start_pos = 0;
    long long pos = 0;
    char datetime_str[20];

    // 用于跟踪文件信息
    typedef struct {
        char filename[256];
        uint64_t total_sections;
        uint64_t found_sections;
        uint64_t first_section_id_found;
        uint64_t last_section_id_found;
        int has_section0;
        int is_corrupted;
        int is_encrypted;
        int is_compressed;
    } FileVerifyInfo;

    FileVerifyInfo* file_info = NULL;
    int file_count = 0;
    int file_capacity = 0;

    printf("Verifying archive: %s\n", archive_name);
    if (g_encryption_enabled) {
        printf("Decryption enabled for verification\n");
    }
    printf("%-30s %-20s %-10s %s\n", "Name", "Modified Time", "Type", "Status");
    printf("------------------------------------------------\n");

    long long filesize = get_file_size(archive_name);

    while (1) {
        pos = find_next_magic(archive, start_pos, filesize);
        if (pos == -1) break;

        if (!read_block_header(archive, &header)) {
            start_pos = pos + 1;
            continue;
        }

        // 格式化时间
        format_datetime(header.mtime, datetime_str, sizeof(datetime_str));

        // 查找或创建文件信息记录
        int file_idx = -1;
        for (int i = 0; i < file_count; i++) {
            if (strcmp(file_info[i].filename, header.filename) == 0) {
                file_idx = i;
                break;
            }
        }

        if (file_idx == -1 && header.magic == MAGIC_NUMBER_FILE) {
            // 新文件
            if (file_count >= file_capacity) {
                file_capacity = file_capacity ? file_capacity * 2 : 16;
                file_info = (FileVerifyInfo*)realloc(file_info,
                    file_capacity * sizeof(FileVerifyInfo));
                if (!file_info) {
                    printf("Error: Out of memory\n");
                    break;
                }
            }

            file_idx = file_count++;
            strcpy(file_info[file_idx].filename, header.filename);
            file_info[file_idx].total_sections = header.total_section_count;
            file_info[file_idx].found_sections = 0;
            file_info[file_idx].first_section_id_found = header.section_id;
            file_info[file_idx].last_section_id_found = header.section_id;
            file_info[file_idx].has_section0 = (header.section_id == 0);
            file_info[file_idx].is_corrupted = 0;
            file_info[file_idx].is_encrypted = (header.flags & FLAG_ENCRYPTED) ? 1 : 0;
            file_info[file_idx].is_compressed = (header.flags & FLAG_COMPRESSED) ? 1 : 0;
        }
        else if (file_idx != -1) {
            // 更新现有文件信息
            file_info[file_idx].found_sections++;
            if (header.section_id < file_info[file_idx].first_section_id_found) {
                file_info[file_idx].first_section_id_found = header.section_id;
            }
            if (header.section_id > file_info[file_idx].last_section_id_found) {
                file_info[file_idx].last_section_id_found = header.section_id;
            }
            if (header.section_id == 0) {
                file_info[file_idx].has_section0 = 1;
            }
        }

        // 使用公共函数验证块头
        validate_block_header(&header, pos, start_pos, &block_num);

        // 根据类型验证
        if (header.magic == MAGIC_NUMBER_DIR) {
            // 目录：只有CRC
            uint32_t stored_crc;
            read_crc32(archive, &stored_crc);
            if (stored_crc != 0) {
                printf("%-30s %-20s %-10s %s (CRC: 0x%08x)\n",
                    header.filename, datetime_str, "<DIR>",
                    "CRC CORRUPTED", stored_crc);
                corrupted_blocks++;
            }
            else {
                printf("%-30s %-20s %-10s %s\n",
                    header.filename, datetime_str, "<DIR>", "OK");
            }
        }
        else if (header.magic == MAGIC_NUMBER_FILE) {
            if (header.section_size == 0) {
                // 空文件
                uint32_t stored_crc;
                read_crc32(archive, &stored_crc);
                if (stored_crc != 0) {
                    printf("%-30s %-20s %-10s %s (CRC: 0x%08x)\n",
                        header.filename, datetime_str, "<EMPTY>",
                        "CRC CORRUPTED", stored_crc);
                    corrupted_blocks++;
                    if (file_idx != -1) file_info[file_idx].is_corrupted = 1;
                }
                else {
                    printf("%-30s %-20s %-10s %s\n",
                        header.filename, datetime_str, "<EMPTY>", "OK");
                }
            }
            else {
                // 普通文件：验证数据CRC
                CRC32_Context ctx;
                crc32_init(&ctx);

                // 读取数据到缓冲区
                uint8_t* data_buffer = (uint8_t*)malloc(header.section_size);
                if (!data_buffer) {
                    printf("Error: Out of memory\n");
                    fclose(archive);
                    free(file_info);
                    return -1;
                }

                size_t actual_read = fread(data_buffer, 1, header.section_size, archive);
                if (header.section_size - actual_read > 0) {
                    printf("Warning: Short read for %s\n", header.filename);
                    memset(data_buffer + actual_read, 0, header.section_size - actual_read);
                }

                // 计算CRC
                crc32_update(&ctx, data_buffer, header.section_size);

                // 如果需要解密
                if (g_encryption_enabled && (header.flags & FLAG_ENCRYPTED)) {
                    uint32_t data_len;
                    if (header.section_size % AES_BLOCK_SIZE != 0) {
                        printf("Warning: Section size is not a multiple of AES_BLOCK_SIZE\n");
                    }
                    process_data_block(data_buffer, header.section_size, header.header_crc32, 0);
                    if (pkcs7_unpad(data_buffer, header.section_size, &data_len) < 0) {
                        printf("Error: PKCS#7 unpad failed\n");
                    }
                }

                uint32_t crc = crc32_final(&ctx);

                // 读取存储的CRC
                uint32_t stored_crc;
                read_crc32(archive, &stored_crc);
                free(data_buffer);

                // 显示每个section的状态
                const char* status;
                if (crc != stored_crc) {
                    status = "DATA CORRUPTED";
                    corrupted_blocks++;
                    if (file_idx != -1) file_info[file_idx].is_corrupted = 1;
                }
                else {
                    status = "OK";
                }

                // 构建标志字符串
                char flags_str[32] = "";
                if (header.flags & FLAG_ENCRYPTED) strcat(flags_str, "encrypted ");
                if (header.flags & FLAG_COMPRESSED) strcat(flags_str, "compressed");

                // 显示section信息
                printf("%-30s %-20s %-10s %s (Section id %llu/%llu, Data Offset %llu, Original Size: %u,Section Size: %u, CRC: 0x%08x%s%s)\n",
                    header.filename, datetime_str, "FILE",
                    status,
                    (unsigned long long)header.section_id,
                    (unsigned long long)header.total_section_count,
                    (unsigned long long)header.data_offset,
                    header.original_size,
                    header.section_size,
                    stored_crc,
                    (header.flags & FLAG_ENCRYPTED) ? ", encrypted" : "",
                    (header.flags & FLAG_COMPRESSED) ? ", compressed" : "");
            }
        }

        start_pos = _ftelli64(archive);
    }

    // 检查文件的完整性（section连续性）
    printf("\nFile Integrity Summary:\n");
    printf("------------------------------------------------\n");

    for (int i = 0; i < file_count; i++) {
        if (file_info[i].total_sections > 0) {
            int file_issues = 0;

            // 检查是否有section 0
            if (!file_info[i].has_section0) {
                printf("Warning: %s - Missing section 0 (first block), found sections %llu-%llu\n",
                    file_info[i].filename,
                    (unsigned long long)file_info[i].first_section_id_found,
                    (unsigned long long)file_info[i].last_section_id_found);
                file_issues++;
                missing_first_blocks++;
            }

            // 检查section数量
            uint64_t actual_sections = file_info[i].last_section_id_found -
                file_info[i].first_section_id_found + 1;
            if (actual_sections != file_info[i].total_sections &&
                file_info[i].total_sections > 0) {
                printf("Warning: %s - Section count mismatch: expected %llu, found %llu (sections %llu-%llu)\n",
                    file_info[i].filename,
                    (unsigned long long)file_info[i].total_sections,
                    (unsigned long long)actual_sections,
                    (unsigned long long)file_info[i].first_section_id_found,
                    (unsigned long long)file_info[i].last_section_id_found);
                file_issues++;
            }

            if (file_issues == 0 && !file_info[i].is_corrupted) {
                char flags_str[32] = "";
                if (file_info[i].is_encrypted) strcat(flags_str, "encrypted");
                if (file_info[i].is_compressed) { 
                    if (file_info[i].is_encrypted) {
                        strcat(flags_str, " ");
                    }
                    strcat(flags_str, "compressed"); 
                }
                if (strlen(flags_str) > 0) {
                    printf("OK: %s - All %llu sections present and intact (%s)\n",
                        file_info[i].filename,
                        (unsigned long long)file_info[i].total_sections,
                        flags_str);
                }
                else {
                    printf("OK: %s - All %llu sections present and intact\n",
                        file_info[i].filename,
                        (unsigned long long)file_info[i].total_sections);
                }
            }
        }
    }

    printf("------------------------------------------------\n");
    fclose(archive);
    free(file_info);

    if (corrupted_blocks == 0 && missing_first_blocks == 0) {
        printf("Archive is intact, all %llu blocks are valid\n",
            (unsigned long long)block_num);
        return 0;
    }
    else {
        printf("Archive issues found:\n");
        printf("  - Corrupted blocks: %d\n", corrupted_blocks);
        printf("  - Files missing first block: %d\n", missing_first_blocks);
        return -1;
    }
}

// 提取文件
int extract_archive(const char* archive_name, char** files, int file_count) {
    FILE* archive = fopen(archive_name, "rb");
    if (!archive) {
        printf("Cannot open archive file: %s\n", archive_name);
        return -1;
    }

    BlockHeader header;
    FileInfo* file_info = NULL;
    int file_info_count = 0;
    int file_info_capacity = 0;
    long long start_pos = 0;
    long long pos = 0;
    uint64_t block_num = 0;
    int result;

    printf("Scanning archive: %s\n", archive_name);
    if (g_encryption_enabled) {
        printf("Decryption enabled for extraction\n");
    }
    if (g_output_path[0] != '\0') {
        printf("Output directory: %s\n", g_output_path);
    }

    // 先扫描归档，收集文件信息
    long long filesize = get_file_size(archive_name);

    while (1) {
        pos = find_next_magic(archive, start_pos, filesize);
        if (pos == -1) break;

        if (!read_block_header(archive, &header)) {
            start_pos = pos + 1;
            continue;
        }

        // 使用公共函数验证块头
        result = validate_block_header(&header, pos, start_pos, &block_num);
        if (result < 0) {
            start_pos = pos + 1;
            continue;
        }

        // 记录文件/目录信息
        int found = -1;
        for (int i = 0; i < file_info_count; i++) {
            if (strcmp(file_info[i].filename, header.filename) == 0) {
                found = i;
                break;
            }
        }

        if (found == -1) {
            // 新文件或目录
            if (file_info_count >= file_info_capacity) {
                file_info_capacity = file_info_capacity ? file_info_capacity * 2 : 16;
                file_info = (FileInfo*)realloc(file_info, file_info_capacity * sizeof(FileInfo));
                if (!file_info) {
                    printf("Error: Out of memory\n");
                    break;
                }
            }
            found = file_info_count++;
            strcpy(file_info[found].filename, header.filename);
            file_info[found].total_size = header.total_size;
            file_info[found].actual_total_size = 0;
            file_info[found].section_count = header.total_section_count;
            file_info[found].actual_section_count = 0;
            file_info[found].next_desired_section_id = 0;
            file_info[found].first_block_offset = _ftelli64(archive) - sizeof(BlockHeader);
            file_info[found].is_directory = (header.magic == MAGIC_NUMBER_DIR);
            file_info[found].is_encrypted = (header.flags & FLAG_ENCRYPTED) ? 1 : 0;
            file_info[found].is_compressed = (header.flags & FLAG_COMPRESSED) ? 1 : 0;
        }
        file_info[found].actual_section_count++;

        // 跳过数据块和CRC
        if (header.magic == MAGIC_NUMBER_FILE && header.section_size > 0) {
            _fseeki64(archive, header.section_size + CRC32_SIZE, SEEK_CUR);
        }
        else {
            // 目录或空文件：只有CRC
            _fseeki64(archive, CRC32_SIZE, SEEK_CUR);
        }

        start_pos = _ftelli64(archive);
    }

    printf("Found %d items in archive\n", file_info_count);

    // 检查是否需要提取所有文件
    int extract_all = (file_count == 0);
    if (!extract_all) {
        // 验证指定的文件是否存在
        for (int i = 0; i < file_count; i++) {
            int found = 0;
            for (int j = 0; j < file_info_count; j++) {
                if (strstr(file_info[j].filename, files[i]) != NULL) {
                    found = 1;
                    printf("Found: %s\n", file_info[j].filename);
                    break;
                }
            }
            if (!found) {
                printf("Warning: File '%s' not found\n", files[i]);
            }
        }
    }

    // 先创建所有目录
    printf("Creating directory structure...\n");
    for (int i = 0; i < file_info_count; i++) {
        if (file_info[i].is_directory) {
            char dir_path[256];
            strcpy(dir_path, file_info[i].filename);
            // 移除末尾的'/'
            size_t len = strlen(dir_path);
            if (len > 0 && dir_path[len - 1] == '/') {
                dir_path[len - 1] = '\0';
            }

            printf("Creating directory: %s\n", dir_path);
            create_directories_with_root(g_output_path, dir_path);
        }
    }

    // 提取文件
    int corrupted_files = 0;
    for (int i = 0; i < file_info_count; i++) {
        // 跳过目录
        if (file_info[i].is_directory) continue;

        // 检查是否需要提取这个文件
        int should_extract = extract_all;
        if (!should_extract) {
            for (int j = 0; j < file_count; j++) {
                if (strstr(file_info[i].filename, files[j]) != NULL) {
                    should_extract = 1;
                    break;
                }
            }
        }

        if (!should_extract) continue;

        printf("Extracting: %s%s%s\n", file_info[i].filename,
            file_info[i].is_encrypted ? " (encrypted)" : "",
            file_info[i].is_compressed ? " (compressed)" : "");

        // 构建输出文件路径
        char output_file_path[MAX_PATH];
        build_output_path(g_output_path, file_info[i].filename, output_file_path, sizeof(output_file_path));

        // 创建文件所在的目录
        char* dir_path = strdup(output_file_path);
        char* dir = dirname(dir_path);
        if (strcmp(dir, ".") != 0 && strcmp(dir, "\\") != 0 && strlen(dir) > 0) {
            create_directories(dir);
        }
        free(dir_path);

        // 打开输出文件
        FILE* outfile = fopen(output_file_path, "wb");
        if (!outfile) {
            printf("Error: Cannot create file %s\n", output_file_path);
            continue;
        }

        // 定位到第一个块
        _fseeki64(archive, file_info[i].first_block_offset, SEEK_SET);
        start_pos = file_info[i].first_block_offset;

        uint64_t write_pos = 0;
        int file_corrupted = 0;
        block_num = 0;

        // 检查section数量（对于非空文件）
        if (file_info[i].total_size > 0 &&
            file_info[i].section_count != file_info[i].actual_section_count) {
            file_corrupted = 1;
            printf("Warning: File '%s' corrupted, desired section count %llu, but only get %llu\n",
                file_info[i].filename, file_info[i].section_count, file_info[i].actual_section_count);
        }

        // 初始化进度显示上下文
        ProgressContext progress;
        progress_init(&progress, file_info[i].total_size, file_info[i].actual_section_count, file_info[i].filename);

        for (uint64_t sid = 0; sid < file_info[i].actual_section_count; sid++) {
            BlockHeader header;
            pos = find_next_magic(archive, start_pos, filesize);
            if (pos == -1) break;

            if (!read_block_header(archive, &header)) {
                start_pos = pos + 1;
                file_corrupted = 1;
                continue;
            }

            // 验证块头
            long long current_pos = _ftelli64(archive) - sizeof(BlockHeader);
            validate_block_header(&header, current_pos, current_pos, &block_num);

            if (header.data_offset != write_pos) {
                printf("Warning: File '%s' section id %llu data offset mismatch: expected 0x%llx, found 0x%llx\n",
                    file_info[i].filename, (unsigned long long)header.section_id,
                    (unsigned long long)header.data_offset, (unsigned long long)write_pos);
                file_corrupted = 1;
                if (header.data_offset < header.total_size) {
                    printf("Seeking to expected offset...\n");
                    if (_fseeki64(outfile, header.data_offset, SEEK_SET) != 0) {
                        printf("Seek failed, error code: %d\n", errno);
                    }
                }
            }

            uint32_t original_len = header.original_size;
            uint32_t data_len = header.section_size;

            // 处理数据（如果有）
            if (data_len > 0) {
                // 计算CRC
                CRC32_Context ctx;
                crc32_init(&ctx);

                // 读取数据
                uint8_t* data_buffer = (uint8_t*)malloc(data_len);
                if (!data_buffer) {
                    printf("Error: Out of memory\n");
                    fclose(outfile);
                    fclose(archive);
                    free(file_info);
                    return -1;
                }

                size_t actual_read = fread(data_buffer, 1, data_len, archive);
                if (data_len - actual_read > 0) {
                    printf("Warning: Short read for %s\n", file_info[i].filename);
                    memset(data_buffer + actual_read, 0, data_len - actual_read);
                }
                long long block_start = _ftelli64(archive) - actual_read;

                // 更新CRC
                crc32_update(&ctx, data_buffer, data_len);

                // 如果需要解密
                if (g_encryption_enabled && (header.flags & FLAG_ENCRYPTED)) {
                    if (data_len % AES_BLOCK_SIZE != 0) {
                        printf("Warning: Section size is not a multiple of AES_BLOCK_SIZE\n");
                    }
                    process_data_block(data_buffer, data_len, header.header_crc32, 0);
                    if (pkcs7_unpad(data_buffer, data_len, &data_len) < 0) {
                        printf("Error: PKCS#7 unpad failed\n");
                        file_corrupted = 1;
                    }
                }

                // 如果需要解压缩
                uint8_t* final_data = data_buffer;
                uint32_t final_len = data_len;

                if (header.flags & FLAG_COMPRESSED) {
                    uint8_t* decompressed = decompress_zstd(data_buffer, data_len, original_len);
                    if (decompressed) {
                        final_data = decompressed;
                        final_len = original_len;
                        free(data_buffer);  // 释放压缩数据
                    }
                    else {
                        printf("Error: Decompression failed for %s section id %llu\n",
                            file_info[i].filename, (unsigned long long)header.section_id);
                        file_corrupted = 1;
                    }
                }

                // 写入文件
                if (final_len != original_len) {
                    file_corrupted = 1;
                    printf("Warning: File '%s' section id %llu size mismatch: expected 0x%llx, found 0x%llx\n",
                        file_info[i].filename, (unsigned long long)header.section_id,
                        (unsigned long long)header.original_size, (unsigned long long)final_len);
                    size_t write_len = final_len > original_len ? original_len : final_len;
                    size_t actual_write = fwrite(final_data, 1, write_len, outfile);
                    int64_t size_diff = (int64_t)original_len - (int64_t)write_len;
                    if (actual_write != write_len) {
                        printf("Error: Failed to write data for %s section id %llu\n",
                         file_info[i].filename, (unsigned long long)header.section_id);
                    }
                    if (size_diff > 0) {
                        printf("Seeking pass the end of file %llu bytes...\n", original_len - write_len);
                        if (_fseeki64(outfile, original_len - write_len, SEEK_CUR) != 0) {
                            printf("Seek failed, error code: %d\n", errno);
                        }
                    }
                }
                else {
                    if (fwrite(final_data, 1, final_len, outfile) != final_len) {
                        printf("Error: Failed to write data for %s section id %llu\n",
                            file_info[i].filename, (unsigned long long)header.section_id);
                    }
                }

                free(final_data);

                // 读取存储的CRC
                uint32_t stored_crc;
                read_crc32(archive, &stored_crc);

                // 验证CRC
                uint32_t crc = crc32_final(&ctx);
                if (crc != stored_crc) {
                    printf("Error: File %s section id %llu CRC check failed\n",
                        file_info[i].filename, (unsigned long long)header.section_id);
                    printf("       Calculated: 0x%08x, Stored: 0x%08x\n", crc, stored_crc);
                    printf("       Corruption location: 0x%llx - 0x%llx\n",
                        (unsigned long long)block_start,
                        (unsigned long long)(block_start + data_len));
                    file_corrupted = 1;
                }

                write_pos = _ftelli64(outfile);
            }
            else {
                // 空文件：跳过CRC
                uint32_t stored_crc;
                read_crc32(archive, &stored_crc);
                // 空文件的CRC应该是0
                if (stored_crc != 0) {
                    printf("Warning: Empty file %s has non-zero CRC 0x%08x\n",
                        file_info[i].filename, stored_crc);
                }
            }

            if (file_info[i].total_size > 0) {
                if (file_info[i].next_desired_section_id != header.section_id) {
                    file_corrupted = 1;
                    printf("Warning: File '%s' corrupted, desired section id %llu, but found %llu\n",
                        file_info[i].filename, file_info[i].next_desired_section_id, header.section_id);
                }
                file_info[i].next_desired_section_id = header.section_id + 1;
                file_info[i].actual_total_size += original_len;

                if (sid + 1 >= file_info[i].actual_section_count &&
                    file_info[i].actual_total_size != file_info[i].total_size) {
                    file_corrupted = 1;
                    printf("Warning: File '%s' corrupted, desired total size %llu bytes, but get %llu bytes\n",
                        file_info[i].filename, file_info[i].total_size, file_info[i].actual_total_size);
                }
            }

            progress_update(&progress, write_pos, header.section_id, 0);

            start_pos = _ftelli64(archive);
        }
        progress_finish(&progress);

        fclose(outfile);

        if (file_corrupted) {
            corrupted_files++;
            char new_file_name[256];
            snprintf(new_file_name, sizeof(new_file_name), "%s.corrupted", output_file_path);
            printf("File %s corrupted, rename to %s\n", output_file_path, new_file_name);
            if (rename(output_file_path, new_file_name) != 0) {
                printf("Rename to %s failed\n", new_file_name);
            }
        }
        else {
            if (file_info[i].total_size == 0) {
                printf("Successfully extracted empty file: %s\n", output_file_path);
            }
            else {
                char flags_str[32] = "";
                if (file_info[i].is_encrypted)
                {
                    if (g_encryption_enabled) {
                        strcat(flags_str, "decrypted");
                    }
                    else {
                        strcat(flags_str, "encrypted");
                    }
                }
                if (file_info[i].is_compressed) strcat(flags_str, " decompressed");
                printf("Successfully extracted: %s (%llu bytes)%s%s%s\n",
                    output_file_path,
                    (unsigned long long)write_pos,
                    strlen(flags_str) > 0 ? " (" : "",
                    flags_str,
                    strlen(flags_str) > 0 ? ")" : "");
            }
        }
    }

    free(file_info);
    fclose(archive);

    if (corrupted_files > 0) {
        printf("Warning: %d files were found corrupted during extraction\n", corrupted_files);
        return -1;
    }
    else {
        printf("Extraction completed successfully\n");
        return 0;
    }
}

// 打印使用帮助
void print_usage(const char* progname) {
    printf("LLawsXX Archive Tool (lxar) - Windows Version (with AES encryption and ZSTD compression)\n");
    printf("Usage:\n");
    printf("  %s archive [-o <output_file>] [-s <size>] [-p <password>] [-z <level>] <directory>   - Create archive\n", progname);
    printf("  %s extract [-o <output_dir>] [-p <password>] <archive>                  - Extract all files\n", progname);
    printf("  %s extract [-o <output_dir>] [-p <password>] <archive> <files>          - Extract specific files\n", progname);
    printf("  %s list <archive>                     - List archive contents\n", progname);
    printf("  %s verify [-p <password>] <archive>                   - Verify archive integrity\n", progname);
    printf("\nOptions:\n");
    printf("  -o, --output <path>        Set output file/directory path\n");
    printf("  -s, --section-size <size>   Set section size (default: 256K)\n");
    printf("                              Supported suffixes: K (KB), M (MB), G (GB)\n");
    printf("  -p, --password <password>   Set encryption password (AES-128 CBC)\n");
    printf("                              Password can be 16 hex bytes (32 chars) or any string\n");
    printf("  -z, --compress <level>      Set ZSTD compression level (1-22, default: 3)\n");
    printf("                              Use -z 0 to disable compression\n");
    printf("\nFeatures:\n");
    printf("  - Supports empty directories\n");
    printf("  - Supports empty files (0 bytes)\n");
    printf("  - ZSTD compression (configurable level)\n");
    printf("  - AES-128 CBC encryption (data only, headers remain unencrypted)\n");
    printf("  - Each section uses its header CRC as IV\n");
    printf("\nExamples:\n");
    printf("  %s archive myfolder\n", progname);
    printf("  %s archive -o myarchive.lxar myfolder\n", progname);
    printf("  %s archive -s 1M -p mypassword -z 5 -o encrypted_compressed.lxar myfolder\n", progname);
    printf("  %s archive -z 0 myfolder                      # Disable compression\n", progname);
    printf("  %s archive -p 00112233445566778899aabbccddeeff -o key.lxar myfolder\n", progname);
    printf("  %s extract -o extracted_files -p mypassword myfolder.lxar\n", progname);
    printf("  %s extract -o output_dir archive.lxar file1.txt file2.txt\n", progname);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // 检查是否是archive命令
    if (strcmp(argv[1], "archive") == 0) {
        // 解析archive命令的参数
        int dir_index = 2;
        int password_index = -1;
        int output_index = -1;
        int compress_index = -1;

        // 检查是否有各种选项
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--section-size") == 0) {
                if (i + 1 < argc) {
                    g_section_size = parse_size(argv[i + 1]);
                    i++;
                }
            }
            else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
                if (i + 1 < argc) {
                    password_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                if (i + 1 < argc) {
                    output_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--compress") == 0) {
                if (i + 1 < argc) {
                    compress_index = i + 1;
                    i++;
                }
            }
            else {
                dir_index = i;
                break;
            }
        }

        // 处理压缩级别
        if (compress_index != -1) {
            int level = parse_compression_level(argv[compress_index]);
            if (level == 0) {
                g_compression_enabled = 0;
                printf("Compression disabled\n");
            }
            else {
                g_compression_enabled = 1;
                g_compression_level = level;
            }
        }

        // 处理密码
        if (password_index != -1) {
            generate_key_from_password(argv[password_index]);
        }

        // 找到目录参数
        if (dir_index >= argc) {
            printf("Error: Missing directory name\n");
            print_usage(argv[0]);
            return 1;
        }

        char archive_name[256];
        if (output_index != -1) {
            // 使用指定的输出文件名
            strncpy(archive_name, argv[output_index], sizeof(archive_name) - 1);
            archive_name[sizeof(archive_name) - 1] = '\0';
        }
        else {
            // 使用默认输出文件名
            snprintf(archive_name, sizeof(archive_name), "%s.lxar", get_last_path_component(argv[dir_index]));
        }

        return create_archive(archive_name, argv[dir_index]);
    }
    else if (strcmp(argv[1], "extract") == 0 && argc >= 3) {
        // 解析extract命令的参数
        int archive_index = 2;
        int password_index = -1;
        int output_index = -1;

        // 检查是否有-p和-o选项
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
                if (i + 1 < argc) {
                    password_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                if (i + 1 < argc) {
                    output_index = i + 1;
                    i++;
                }
            }
            else {
                archive_index = i;
                break;
            }
        }

        // 处理密码
        if (password_index != -1) {
            generate_key_from_password(argv[password_index]);
        }

        // 处理输出路径
        if (output_index != -1) {
            strncpy(g_output_path, argv[output_index], MAX_PATH - 1);
            g_output_path[MAX_PATH - 1] = '\0';
            // 创建输出目录
            create_directories(g_output_path);
        }

        if (archive_index + 1 < argc) {
            // 有指定文件列表
            return extract_archive(argv[archive_index], &argv[archive_index + 1], argc - archive_index - 1);
        }
        else {
            // 提取所有文件
            return extract_archive(argv[archive_index], NULL, 0);
        }
    }
    else if (strcmp(argv[1], "list") == 0 && argc >= 3) {
        return list_archive(argv[2]);
    }
    else if (strcmp(argv[1], "verify") == 0 && argc >= 3) {
        // 解析verify命令的参数
        int archive_index = 2;
        int password_index = -1;

        // 检查是否有-p选项
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
                if (i + 1 < argc) {
                    password_index = i + 1;
                    i++;
                }
            }
            else {
                archive_index = i;
                break;
            }
        }

        // 处理密码
        if (password_index != -1) {
            generate_key_from_password(argv[password_index]);
        }

        return verify_archive(argv[archive_index]);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}