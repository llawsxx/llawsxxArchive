#define _CRT_SECURE_NO_WARNINGS
/*
 * lxar - LLawsXX ARchive format - Windows版本 (支持AES加密、ZSTD压缩和分卷)
 *
 *
 * 使用方法:
 *   lxar archive [-o <输出文件>] [-s <size>] [-v <size>] [-p <password>] [-z <level>] <文件或目录>  - 创建归档
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
#include "fec.h"
#include <windows.h>
#include <direct.h>
#include <zstd.h>
#include <zdict.h>
#include <errno.h>
#include <limits.h>
#include <wchar.h>

#define DEFAULT_SECTION_SIZE (256 * 1024)  // 默认256KB
#define MIN_SECTION_SIZE (1024)            // 最小1KB
#define MAX_SECTION_SIZE (64 * 1024 * 1024) // 最大64MB
#define MIN_RS_GROUP_SIZE (1 * 1024 * 1024) //最小1MB
#define MAX_RS_GROUP_SIZE (16ULL * 1024 * 1024 * 1024) // 最大16GB

#define DEFAULT_VOLUME_SIZE (0)            // 默认不分卷
#define MIN_VOLUME_SIZE (4 * 1024 * 1024)  // 最小分卷大小4MB
#define MAX_VOLUME_SIZE (4LL * 1024 * 1024 * 1024 * 1024) // 最大4TB
#define MAX_VOLUME_NUMBER 99999             // 最大分卷编号支持到99999

#define MAGIC_NUMBER_FILE 0x424C4F43  // "BLOC" in ASCII
#define MAGIC_NUMBER_DIR 0x44495200   // "DIR\0" in ASCII
#define MAX_PATH_LEN MAX_PATH
#define PATH_LEN_FOR_PROC (MAX_PATH * 2)
#define CRC32_SIZE 4

 // 标志位定义
#define FLAG_ENCRYPTED 0x01  // 数据已加密
#define FLAG_COMPRESSED 0x02  // 数据已压缩 (ZSTD)
#define FLAG_RS_REDUNDANT 0x04  // RS冗余块
#define FLAG_DICT_COMPRESSED 0x08  // 使用ZSTD字典压缩
#define FLAG_RS_EXTENDED_FIELD 0x10  // 保留给较新RS编码格式；本版本不支持

// 默认压缩级别
#define DEFAULT_COMPRESSION_LEVEL 3

// 字典训练相关常量
#define MAX_DICT_SIZE (128 * 1024 * 1024)  // 最大字典大小128MB
#define MIN_TRAINING_SAMPLES 8             // 最小训练样本数

// 字典头部信息（存储在压缩数据之前）
#pragma pack(push, 1)
typedef struct {
    uint32_t dict_id;          // 字典ID
    uint32_t data_size;        // 原始数据大小（压缩前）
} DictDataHeader;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct {
    uint32_t magic;           // 4B Magic number (FILE or DIR)
    char filename[MAX_PATH_LEN];       // MAX_PATH_LEN Filename
    uint64_t mtime;           // 8B Modification time (UNIX timestamp)
    uint64_t total_size;      // 8B Total file size (0 for directories)
    uint64_t block_id;        // 8B Block ID (0 for directories)
    uint64_t block_group_id;  // 8B Block group ID (0 for directories)
    uint64_t section_id;      // 8B Section ID (starts from 0)
    uint32_t section_size;    // 4B Section size (压缩后的数据大小，0 for directories)
    uint32_t original_size;   // 4B 原始数据大小 (压缩前，用于解压缩)
    uint64_t total_section_count;   // 8B total section count (0 for directories)
    uint64_t data_offset;     // 8B 数据在原文件中的偏移量
    uint32_t flags;           // 4B 标志位 (如: 0x01 = 加密, 0x02 = 压缩, 0x04 = 冗余块)
    uint32_t header_crc32;    // 4B header CRC32
    // Data follows immediately for files
    // Finally 4B CRC32 for files
} BlockHeader;
#pragma pack(pop)

// RS数据分块信息
#pragma pack(push, 1)
typedef struct {
    uint64_t block_index;     // 数据分块所在的block的block_index
    uint32_t offset;          // 相对于这个block开头的字节偏移
    uint32_t size;            // 这个数据分块的大小
    uint32_t crc32;           // 这个数据分块的校验值
} RSDataChunkInfo;
#pragma pack(pop)

// RS冗余块的数据头
#pragma pack(push, 1)
typedef struct {
    uint32_t chunk_count;     // 数据分块的数量
    uint32_t chunk_info_size; // 每个chunk info的大小
    uint32_t data_size;       // 冗余数据的实际大小
    // 后面跟着chunk_count个RSDataChunkInfo
    // 最后是实际的冗余数据
} RSBlockHeader;
#pragma pack(pop)


// 字典上下文结构体
typedef struct {
    uint8_t* dict_data;        // 字典数据
    size_t dict_size;          // 字典大小
    uint32_t dict_id;          // 字典ID（基于内容的CRC32哈希）
    ZSTD_CDict* cdict;         // 压缩字典引用
    ZSTD_DDict* ddict;         // 解压字典引用
    ZSTD_CCtx* cctx;           // 压缩上下文（复用）
    ZSTD_DCtx* dctx;           // 解压上下文（复用）
    int is_loaded;             // 是否已加载
} DictContext;

typedef struct {
    char filename[MAX_PATH_LEN];
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

// 分卷文件管理结构
typedef struct {
    FILE* current_file;        // 当前分卷文件句柄
    char base_name[512];       // 基础文件名（不含分卷编号）
    uint64_t volume_size;       // 分卷大小（字节，0表示不分卷）
    uint64_t current_volume;    // 当前分卷编号（从1开始，不分卷时始终为1）
    uint64_t current_pos;       // 当前分卷中的写入位置
    int is_open;                // 当前文件是否打开
    uint64_t total_written;     // 总共写入的数据量
    int is_multi_volume;        // 是否多分卷模式
} VolumeContext;

typedef struct {
    char current_file[512];     // 当前正在读取的文件名
    char base_name[512];        // 基础文件名
    uint64_t current_volume;     // 当前分卷编号
    FILE* file;                 // 当前文件句柄
    uint64_t file_size;         // 当前文件大小
    int is_open;                // 是否打开
    int is_multi_volume;        // 是否多分卷模式
} VolumeReadContext;

typedef struct {
    uint64_t block_id;
    uint64_t volume_number;
    long long offset;
} ArchiveBlockIndexEntry;

typedef struct {
    ArchiveBlockIndexEntry* entries;
    size_t count;
    size_t capacity;
} ArchiveBlockIndex;

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

typedef struct DataBlock{
    uint64_t block_index;
    uint8_t* data;
    uint32_t size;
    uint32_t capacity;
    struct DataBlock* next;
} DataBlock;


typedef struct {
    DataBlock* front,*rear;
    uint64_t current_block_index;
    uint64_t total_size;
} DataGroupContext;


typedef struct ReassembledBlock {
    uint64_t block_index;      // 原始block索引
    uint32_t block_offset;   //在Block数据中的偏移
    uint64_t original_offset;   //在原数据中的偏移
    uint32_t size;              // 重组块的实际大小
    uint32_t crc32;
    struct ReassembledBlock* next;
} ReassembledBlock;


typedef struct {
    uint8_t* data;
    uint64_t total_size;        // 重组数据总大小
    uint64_t split_size;        // 分割大小
    ReassembledBlock* block_info; // 重组块信息链表
    uint32_t block_count;       // 重组块数量
} ReassembledContext;

// 修复块信息
typedef struct {
    uint64_t block_id;
    uint64_t section_id;
    uint64_t total_sections;
    uint32_t block_size;
    uint32_t section_size;
    DataBlock* owner;
    uint8_t* data;
    uint8_t* payload_data;
} RepairBlockInfo;



// 全局变量
int total_files_processed = 0;
int total_dirs_processed = 0;
VolumeContext* g_vol_ctx = NULL;        // 分卷写入上下文指针
VolumeReadContext* g_vol_read_ctx = NULL; // 分卷读取上下文指针
DataGroupContext* g_group_ctx = NULL; // 数据组上下文指针
uint32_t g_section_size = DEFAULT_SECTION_SIZE;  // 全局section size
uint64_t g_volume_size = DEFAULT_VOLUME_SIZE;    // 分卷大小（0表示不分卷）
uint8_t g_encryption_key[16] = { 0 };  // AES-128密钥
int g_encryption_enabled = 0;        // 是否启用加密
int g_compression_enabled = 1;        // 是否启用压缩（默认开启）
int g_compression_level = DEFAULT_COMPRESSION_LEVEL;  // 压缩级别
char g_output_path[PATH_LEN_FOR_PROC] = { 0 }; // 输出路径
// 添加全局变量来保存输入根路径
const char* g_input_root_path = NULL;
int g_single_file_input = 0;
int g_error_count = 0;           // 错误计数
int g_warning_count = 0;         // 警告计数
uint64_t g_current_block_index = 0;   // 当前块索引计数器
uint64_t g_current_block_group_index = 0;   // 当前块组索引计数器

// RS冗余相关全局变量
int g_rs_enabled = 0;                // 是否启用RS冗余
int g_rs_data_shards = 0;            // RS数据分片数
int g_rs_parity_shards = 0;          // RS校验分片数
int g_rs_fixed_size_enabled = 0;     // 是否按固定字节数生成RS冗余
uint64_t g_rs_fixed_size = 0;         // 目标RS冗余字节数
uint64_t g_rs_group_size = 512 * 1024 * 1024;
// 全局字典上下文
DictContext* g_dict_ctx = NULL;

// 函数声明
size_t archive_write(const void* ptr, size_t size, int next_volume_if_needed,int is_write_rs);
size_t archive_read(void* ptr, size_t size);
int archive_seek(long long offset, int origin);
long long archive_tell(void);
int rs_group_reassemble_and_write(DataGroupContext* group_ctx, int parity_shards_count, uint64_t group_index,uint32_t split_count);
long long find_next_magic(FILE* file, long long start_pos, long long file_size);
int extract_archive(const char* archive_name, char** files, int file_count);
int extract_archive_with_repair(const char* archive_name, char** files, int file_count);

// UTF-16 转 UTF-8，返回 malloc 分配的字符串，调用者负责 free
char* utf16_to_utf8(const wchar_t* utf16) {
    if (!utf16) return NULL;

    // 计算所需缓冲区大小
    int size = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL);
    if (size == 0) return NULL;

    char* utf8 = (char*)malloc(size);
    if (!utf8) return NULL;

    // 执行转换
    if (WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, size, NULL, NULL) == 0) {
        free(utf8);
        return NULL;
    }

    return utf8;
}


// UTF-8 转 UTF-16，返回 malloc 分配的宽字符串，调用者负责 free
wchar_t* utf8_to_utf16(const char* utf8) {
    if (!utf8) return NULL;

    // 计算所需缓冲区大小（宽字符数，含结尾 null）
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (size == 0) {
        return NULL;
    }

    wchar_t* utf16 = (wchar_t*)malloc(size * sizeof(wchar_t));
    if (!utf16) return NULL;

    // 执行转换
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, utf16, size) == 0) {
        free(utf16);
        return NULL;
    }

    return utf16;
}

FILE* fopen_utf8(const char* filename, const char* mode) {
    wchar_t* wfilename = utf8_to_utf16(filename);
    wchar_t* wmode = utf8_to_utf16(mode);

    if (!wfilename || !wmode) {
        free(wfilename);
        free(wmode);
        return NULL;
    }

    FILE* fp = _wfopen(wfilename, wmode);

    free(wfilename);
    free(wmode);
    return fp;
}

int rename_utf8(const char* old_path, const char* new_path) {
    wchar_t* old_wpath = utf8_to_utf16(old_path);
    wchar_t* new_wpath = utf8_to_utf16(new_path);

    if (!old_wpath || !new_wpath) {
        free(old_wpath);
        free(new_wpath);
        errno = EINVAL;
        return -1;
    }

    int result = _wrename(old_wpath, new_wpath);
    int saved_errno = errno;
    free(old_wpath);
    free(new_wpath);
    errno = saved_errno;
    return result;
}

int remove_utf8(const char* path) {
    wchar_t* wpath = utf8_to_utf16(path);
    if (!wpath) {
        errno = EINVAL;
        return -1;
    }

    int result = _wremove(wpath);
    int saved_errno = errno;
    free(wpath);
    errno = saved_errno;
    return result;
}

int stat64_utf8(const char* path, struct _stat64* buffer) {
    wchar_t* wpath = utf8_to_utf16(path);
    if (!wpath) return -1;

    int result = _wstat64(wpath, buffer);

    free(wpath);
    return result;
}

int mkdir_utf8(const char* pathname) {
    wchar_t* wpath = utf8_to_utf16(pathname);

    if (!wpath) {
        return -1;  // 转换失败
    }

    // _wmkdir 创建目录，成功返回0，失败返回-1
    int result = _wmkdir(wpath);

    free(wpath);
    return result;
}

// 初始化字典上下文
DictContext* init_dict_context(void) {
    DictContext* ctx = (DictContext*)malloc(sizeof(DictContext));
    if (!ctx) return NULL;

    ctx->dict_data = NULL;
    ctx->dict_size = 0;
    ctx->dict_id = 0;
    ctx->cdict = NULL;
    ctx->ddict = NULL;
    ctx->cctx = NULL;
    ctx->dctx = NULL;
    ctx->is_loaded = 0;

    return ctx;
}

// 基于字典数据计算字典ID（CRC32哈希）
uint32_t calculate_dict_id(const uint8_t* dict_data, size_t dict_size) {
    return crc32_calc(dict_data, (uint32_t)dict_size);
}

// 释放字典上下文
void free_dict_context(DictContext* ctx) {
    if (!ctx) return;

    if (ctx->cctx) {
        ZSTD_freeCCtx(ctx->cctx);
        ctx->cctx = NULL;
    }

    if (ctx->dctx) {
        ZSTD_freeDCtx(ctx->dctx);
        ctx->dctx = NULL;
    }

    if (ctx->cdict) {
        ZSTD_freeCDict(ctx->cdict);
        ctx->cdict = NULL;
    }

    if (ctx->ddict) {
        ZSTD_freeDDict(ctx->ddict);
        ctx->ddict = NULL;
    }

    if (ctx->dict_data) {
        free(ctx->dict_data);
        ctx->dict_data = NULL;
    }

    free(ctx);
}

// 从文件加载字典（修正版 - 支持大文件）
int load_dict_from_file(const char* dict_file) {
    struct __stat64 st;
    if (stat64_utf8(dict_file, &st) != 0) {
        printf("Error: Cannot access dictionary file: %s\n", dict_file);
        return -1;
    }

    // 使用64位文件大小
    uint64_t file_size = st.st_size;

    if (file_size == 0) {
        printf("Error: Dictionary file is empty: %s\n", dict_file);
        return -1;
    }

    if (file_size > MAX_DICT_SIZE) {
        printf("Error: Dictionary file too large: %llu bytes (max: %d bytes, %.2f MB)\n",
            (unsigned long long)file_size, MAX_DICT_SIZE, MAX_DICT_SIZE / (1024.0 * 1024.0));
        return -1;
    }

    printf("Loading dictionary from: %s\n", dict_file);
    printf("  - Size: %llu bytes (%.2f KB)\n",
        (unsigned long long)file_size, file_size / 1024.0);

    // 读取字典数据
    uint8_t* dict_data = (uint8_t*)malloc((size_t)file_size);
    if (!dict_data) {
        printf("Error: Out of memory for dictionary (%llu bytes)\n", (unsigned long long)file_size);
        return -1;
    }

    FILE* f = fopen_utf8(dict_file, "rb");
    if (!f) {
        printf("Error: Cannot open dictionary file: %s\n", dict_file);
        free(dict_data);
        return -1;
    }

    // 分块读取，避免单次读取过大
    size_t total_read = 0;
    size_t remaining = (size_t)file_size;

    while (remaining > 0) {
        size_t chunk_size = remaining > (16 * 1024 * 1024) ? (16 * 1024 * 1024) : remaining;
        size_t read_size = fread(dict_data + total_read, 1, chunk_size, f);

        if (read_size == 0) {
            if (ferror(f)) {
                printf("Error: Read error at offset %zu\n", total_read);
                fclose(f);
                free(dict_data);
                return -1;
            }
            break;
        }

        total_read += read_size;
        remaining -= read_size;
    }

    fclose(f);

    if (total_read != file_size) {
        printf("Error: Failed to read entire dictionary (got %zu, expected %llu)\n",
            total_read, (unsigned long long)file_size);
        free(dict_data);
        return -1;
    }

    // 初始化或重置字典上下文
    if (g_dict_ctx) {
        free_dict_context(g_dict_ctx);
    }

    g_dict_ctx = init_dict_context();
    if (!g_dict_ctx) {
        free(dict_data);
        return -1;
    }

    g_dict_ctx->dict_data = dict_data;
    g_dict_ctx->dict_size = total_read;
    g_dict_ctx->dict_id = calculate_dict_id(dict_data, total_read);
    g_dict_ctx->is_loaded = 1;

    // 创建压缩上下文并创建CDict
    g_dict_ctx->cctx = ZSTD_createCCtx();
    if (!g_dict_ctx->cctx) {
        printf("Error: Failed to create compression context\n");
        free_dict_context(g_dict_ctx);
        g_dict_ctx = NULL;
        return -1;
    }

    g_dict_ctx->cdict = ZSTD_createCDict(dict_data, total_read, g_compression_level);
    if (!g_dict_ctx->cdict) {
        printf("Error: Failed to create compression dictionary reference\n");
        free_dict_context(g_dict_ctx);
        g_dict_ctx = NULL;
        return -1;
    }

    // 创建解压上下文并创建DDict
    g_dict_ctx->dctx = ZSTD_createDCtx();
    if (!g_dict_ctx->dctx) {
        printf("Error: Failed to create decompression context\n");
        free_dict_context(g_dict_ctx);
        g_dict_ctx = NULL;
        return -1;
    }

    g_dict_ctx->ddict = ZSTD_createDDict(dict_data, total_read);
    if (!g_dict_ctx->ddict) {
        printf("Error: Failed to create decompression dictionary reference\n");
        free_dict_context(g_dict_ctx);
        g_dict_ctx = NULL;
        return -1;
    }

    printf("Dictionary loaded successfully:\n");
    printf("  - File: %s\n", dict_file);
    printf("  - Size: %zu bytes (%.2f KB)\n", g_dict_ctx->dict_size,
        g_dict_ctx->dict_size / 1024.0);
    printf("  - ID: 0x%08x\n", g_dict_ctx->dict_id);
    printf("  - Compression level: %d\n", g_compression_level);

    return 0;
}


// 全局块索引计数器管理
uint64_t get_next_block_index(void) {
    return g_current_block_index++;
}

DataGroupContext* init_data_group_context() {
    DataGroupContext* context = (DataGroupContext*)malloc(sizeof(DataGroupContext));
    if (context == NULL) {
        return NULL;
    }
    context->front = NULL;
    context->rear = NULL;
    context->total_size = 0;
    context->current_block_index = 0;
    return context;
}

DataBlock* create_data_block(uint64_t block_index, uint32_t capacity) {
    DataBlock* block = (DataBlock*)malloc(sizeof(DataBlock));
    if (block == NULL) {
        return NULL;
    }

    block->block_index = block_index;
    block->size = 0;  // 初始没有数据
    block->capacity = capacity;
    block->next = NULL;

    // 预分配空间
    if (capacity > 0) {
        block->data = (uint8_t*)malloc(capacity);
        if (block->data == NULL) {
            free(block);
            return NULL;
        }
        memset(block->data, 0, capacity);  // 初始化为0
    }
    else {
        block->data = NULL;
    }

    return block;
}

DataBlock* find_data_block(DataGroupContext* context, uint64_t block_index) {
    if (context == NULL || context->front == NULL) {
        return NULL;
    }
    if (context->rear->block_index == block_index) return context->rear;

    DataBlock* current = context->front;
    while (current != NULL) {
        if (current->block_index == block_index) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}


int alloc_data_block(DataGroupContext* context, uint64_t block_index, uint32_t capacity) {
    if (context == NULL) {
        return -1;
    }

    // 检查是否已存在
    DataBlock* existing = find_data_block(context, block_index);
    if (existing != NULL) {
        return -2;
    }

    DataBlock* new_block = create_data_block(block_index, capacity);
    if (new_block == NULL) {
        return -1;
    }

    // 空链表
    if (context->front == NULL) {
        context->front = context->rear = new_block;
        return 0;
    }

    // 快速路径：通常 block_index 应该 >= rear->block_index，直接追加到尾部
    if (block_index >= context->rear->block_index) {
        context->rear->next = new_block;
        context->rear = new_block;
        return 0;
    }

    // 慢速路径：插入到中间或最前
    if (block_index < context->front->block_index) {
        new_block->next = context->front;
        context->front = new_block;
        return 0;
    }

    DataBlock* prev = context->front;
    DataBlock* cur = context->front->next;

    while (cur != NULL && cur->block_index < block_index) {
        prev = cur;
        cur = cur->next;
    }

    new_block->next = cur;
    prev->next = new_block;

    return 0;
}


int write_to_data_block(DataGroupContext* context, uint64_t block_index,
    const uint8_t* data, uint32_t data_size) {
    if (context == NULL || data == NULL || data_size == 0) {
        return -1;
    }

    DataBlock* block = find_data_block(context, block_index);
    if (block == NULL) {
        return -2;  // 数据块不存在
    }

    // 检查容量
    if (block->size + data_size > block->capacity) {
        return -3;  // 容量不足
    }

    // 追加数据
    memcpy(block->data + block->size, data, data_size);
    block->size += data_size;
    context->total_size += data_size;

    return 0;
}

int expand_data_block(DataGroupContext* context, uint64_t block_index, uint32_t new_capacity) {
    DataBlock* block = find_data_block(context, block_index);
    if (block == NULL) {
        return -1;
    }

    if (new_capacity <= block->capacity) {
        return -2;  // 新容量不大于当前容量
    }

    uint8_t* new_data = (uint8_t*)realloc(block->data, new_capacity);
    if (new_data == NULL) {
        return -3;  // 内存分配失败
    }

    block->data = new_data;
    // 初始化新增部分为0
    memset(block->data + block->capacity, 0, new_capacity - block->capacity);
    block->capacity = new_capacity;

    return 0;
}

int init_data_block(DataGroupContext* context, uint64_t block_index, uint32_t capacity) {
    context->current_block_index = block_index;
    DataBlock* block = find_data_block(context, block_index);
    if (block == NULL) {
        // 不存在，创建新块
        return alloc_data_block(context, block_index, capacity);
    }
    else {
        // 存在但容量不足，扩展容量
        if (capacity > block->capacity) {
            return expand_data_block(context, block_index, capacity);
        }
    }
    return 0;
}


void print_data_group_context(DataGroupContext* context) {
    if (context == NULL) {
        printf("Context is NULL\n");
        return;
    }

    printf("DataGroupContext: total_size = %llu\n", (unsigned long long)context->total_size);
    printf("DataBlocks:\n");

    DataBlock* current = context->front;
    int index = 0;
    while (current != NULL) {
        printf("  Block[%d]: index=%llu, size=%u/%u, data=",
            index++, (unsigned long long)current->block_index,
            current->size, current->capacity);

        if (current->data != NULL && current->size > 0) {
            int print_len = current->size < 32 ? current->size : 32;
            for (int i = 0; i < print_len; i++) {
                printf("%02X ", current->data[i]);
            }
            if (current->size > 32) {
                printf("...");
            }
        }
        else {
            printf("(empty)");
        }
        printf("\n");
        current = current->next;
    }
}

uint8_t* get_data_block_data(DataGroupContext* context, uint64_t block_index) {
    DataBlock* block = find_data_block(context, block_index);
    if (block == NULL) {
        return NULL;
    }
    return block->data;
}

uint32_t get_data_block_size(DataGroupContext* context, uint64_t block_index) {
    DataBlock* block = find_data_block(context, block_index);
    if (block == NULL) {
        return 0;
    }
    return block->size;
}

void free_data_group_context(DataGroupContext* context) {
    if (context == NULL) {
        return;
    }

    DataBlock* current = context->front;
    while (current != NULL) {
        DataBlock* next = current->next;
        if (current->data != NULL) {
            free(current->data);
        }
        free(current);
        current = next;
    }

    free(context);
}

void reset_data_group_context(DataGroupContext* context) {
    if (context == NULL) {
        return;
    }

    DataBlock* current = context->front;
    while (current != NULL) {
        DataBlock* next = current->next;
        if (current->data != NULL) {
            free(current->data);
        }
        free(current);
        current = next;
    }

    context->front = context->rear = NULL;
    context->total_size = 0;
    context->current_block_index = 0;
}


ReassembledBlock* create_reassembled_block(uint64_t block_index, uint32_t block_offset, uint64_t original_offset, uint32_t size, uint32_t crc32) {
    ReassembledBlock* block = (ReassembledBlock*)malloc(sizeof(ReassembledBlock));
    if (block == NULL) {
        return NULL;
    }
    block->block_index = block_index;
    block->block_offset = block_offset;
    block->original_offset = original_offset;
    block->size = size;
    block->crc32 = crc32;
    block->next = NULL;
    return block;
}

int add_reassembled_block_info(ReassembledContext* ctx, uint64_t block_index, uint32_t block_offset,
    uint64_t original_offset, uint32_t size, uint32_t crc32) {
    if (ctx == NULL) return -1;

    ReassembledBlock* new_block = create_reassembled_block(block_index, block_offset, original_offset, size, crc32);
    if (new_block == NULL) return -1;

    if (ctx->block_info == NULL) {
        ctx->block_info = new_block;
    }
    else {
        ReassembledBlock* current = ctx->block_info;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_block;
    }
    ctx->block_count++;
    return 0;
}

uint64_t round_up_to_multiple(uint64_t x, uint64_t multiple) {
    return (x + multiple - 1) / multiple * multiple;
}

void free_reassembled_info(ReassembledContext* info);

ReassembledContext* reassemble_data_by_size(DataGroupContext* context, uint64_t split_size) {
    if (context == NULL || context->front == NULL || split_size == 0) {
        return NULL;
    }

    // 计算总数据大小
    uint64_t total_data_size = context->total_size;
    uint64_t aligned_total_data_size = round_up_to_multiple(total_data_size, split_size);
    if (total_data_size == 0) {
        return NULL;
    }
    if (split_size > UINT32_MAX || aligned_total_data_size > SIZE_MAX) {
        printf("Error: RS group or shard size exceeds supported limits\n");
        return NULL;
    }

    // 分配重组后的数据缓冲区，分配aligned_total_data_size的大小，那么后面就可以直接用reassembled_data的指针组data_shards了
    uint8_t* reassembled_data = (uint8_t*)malloc((size_t)aligned_total_data_size);
    if (reassembled_data == NULL) {
        return NULL;
    }

    //最后一段需要设0
    if (aligned_total_data_size > total_data_size) {
        memset(reassembled_data + (size_t)total_data_size, 0, (size_t)(aligned_total_data_size - total_data_size));
    }

    // 创建重组上下文
    ReassembledContext* result = (ReassembledContext*)malloc(sizeof(ReassembledContext));
    if (result == NULL) {
        free(reassembled_data);
        return NULL;
    }

    memset(result, 0, sizeof(ReassembledContext));
    result->data = reassembled_data;
    result->total_size = total_data_size;
    result->split_size = split_size;
    result->block_info = NULL;
    result->block_count = 0;

    // 第一步：按顺序拷贝所有数据到重组缓冲区
    uint64_t current_offset = 0;
    DataBlock* current_block = context->front;

    while (current_block != NULL && current_block->size > 0) {
        if (current_block->data != NULL) {
            memcpy(reassembled_data + (size_t)current_offset, current_block->data, current_block->size);
            /* The serialized block is already in the archive. Release its
             * input buffer as soon as it has been copied into RS storage. */
            free(current_block->data);
            current_block->data = NULL;
            current_offset += current_block->size;
        }
        current_block = current_block->next;
    }

    // 第二步：构建原始块在重组缓冲区中的位置映射
    typedef struct {
        uint64_t block_index;
        uint64_t reassembled_offset;  // 在重组缓冲区中的起始偏移
        uint32_t size;                 // 块大小
    } BlockMapping;

    // 统计有效块数量
    uint32_t block_count = 0;
    current_block = context->front;
    while (current_block != NULL) {
        if (current_block->size > 0) {
            block_count++;
        }
        current_block = current_block->next;
    }

    // 分配映射数组
    if (block_count == 0 || block_count > SIZE_MAX / sizeof(BlockMapping)) {
        free(reassembled_data);
        free(result);
        return NULL;
    }
    BlockMapping* mappings = (BlockMapping*)malloc(sizeof(BlockMapping) * block_count);
    if (mappings == NULL) {
        free(reassembled_data);
        free(result);
        return NULL;
    }

    // 填充映射信息
    uint32_t mapping_idx = 0;
    uint64_t offset = 0;
    current_block = context->front;
    while (current_block != NULL) {
        if (current_block->size > 0) {
            mappings[mapping_idx].block_index = current_block->block_index;
            mappings[mapping_idx].reassembled_offset = offset;
            mappings[mapping_idx].size = current_block->size;
            mapping_idx++;
            offset += current_block->size;
        }
        current_block = current_block->next;
    }

    // 第三步：按照分割大小创建重组块，并记录每个重组块对应的原始块信息
    uint64_t reassembled_offset = 0;
    uint64_t remaining_data = total_data_size;

    while (remaining_data > 0) {
        uint32_t current_split_size = (uint32_t)((remaining_data > split_size) ? split_size : remaining_data);

        // 计算当前重组块在重组缓冲区中的范围
        uint64_t segment_start = reassembled_offset;
        uint64_t segment_end = reassembled_offset + current_split_size - 1;

        // 遍历所有原始块，找出与当前重组块有重叠的原始块
        for (uint32_t i = 0; i < block_count; i++) {
            uint64_t block_start = mappings[i].reassembled_offset;
            uint64_t block_end = mappings[i].reassembled_offset + mappings[i].size - 1;

            // 检查是否有重叠
            if (segment_start >= block_start && segment_start <= block_end) {
                // 计算在原始块中的偏移
                uint32_t block_offset = (uint32_t)(segment_start - block_start);

                uint32_t crc32 = crc32_calc(reassembled_data + (size_t)segment_start, current_split_size);
                // 记录重组块信息
                if (add_reassembled_block_info(result, mappings[i].block_index, block_offset,
                    (uint64_t)segment_start, current_split_size, crc32) != 0) {
                    printf("Error: Out of memory for RS shard metadata\n");
                    free(mappings);
                    free_reassembled_info(result);
                    return NULL;
                }
            }
        }

        reassembled_offset += current_split_size;
        remaining_data -= current_split_size;
    }

    free(mappings);
    return result;
}

// 计算切割大小（根据总大小和切割份数）
// 返回每个切割块的大小（最后一块可能小于这个大小）
uint64_t calculate_split_size_by_count(uint64_t total_size, uint32_t split_count) {
    if (split_count == 0) {
        return 0;
    }

    // 计算基础切割大小
    uint64_t base_size = (total_size + split_count - 1) / split_count;
    return base_size;
}


ReassembledContext* reassemble_data_by_count(DataGroupContext* context, uint32_t split_count) {
    if (context == NULL || context->front == NULL || split_count == 0) {
        return NULL;
    }

    // 计算总数据大小
    uint64_t total_data_size = context->total_size;
    if (total_data_size == 0) {
        return NULL;
    }

    // 根据总大小和切割份数计算切割大小
    uint64_t split_size = calculate_split_size_by_count(total_data_size, split_count);

    // 调用按大小切割的函数
    return reassemble_data_by_size(context, split_size);
}

// 打印详细重组信息
void print_reassembled_info(ReassembledContext* ctx) {
    if (ctx == NULL) {
        printf("Detailed reassembled context is NULL\n");
        return;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                        Reassembled Data Info                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ Total size: %-10llu bytes    Split size: %-10llu bytes    ║\n",
        (unsigned long long)ctx->total_size, (unsigned long long)ctx->split_size);
    printf("║ Reassembled block count: %-10u                                    ║\n",
        ctx->block_count);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");

    ReassembledBlock* current = ctx->block_info;
    int index = 0;
    if(current != NULL) {
        printf("\n┌── Reassembled Block[%d] ──────────────────────────────────────┐\n", index);
        printf("├───────────────────────────────────────────────────────────────┤\n");
        printf("│ Original Blocks:                                             │\n");

        int ref_index = 0;
        while (current != NULL) {
            printf("│   [%d] block_index=%-8llu block offset=%-8u offset=%-8llu size=%-8u    │\n",
                ref_index, (unsigned long long)current->block_index , current->block_offset,
                (unsigned long long)current->original_offset, current->size);
            current = current->next;
            ref_index++;
        }
    }
}


// 释放按块维度的信息
void free_reassembled_info(ReassembledContext* info) {
    if (!info) return;

    ReassembledBlock* current = info->block_info;
    while (current != NULL) {
        ReassembledBlock* next = current->next;
        free(current);
        current = next;
    }
    free(info->data);
    free(info);
}



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
    memcpy(be->filename, host->filename, MAX_PATH_LEN);
    be->mtime = htobe64(host->mtime);
    be->total_size = htobe64(host->total_size);
    be->section_id = htobe64(host->section_id);
    be->block_id = htobe64(host->block_id);
    be->block_group_id = htobe64(host->block_group_id);
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
    memcpy(host->filename, be->filename, MAX_PATH_LEN);
    host->mtime = be64toh(be->mtime);
    host->total_size = be64toh(be->total_size);
    host->block_id = be64toh(be->block_id);
    host->block_group_id = be64toh(be->block_group_id);
    host->section_id = be64toh(be->section_id);
    host->section_size = be32toh(be->section_size);
    host->total_section_count = be64toh(be->total_section_count);
    host->data_offset = be64toh(be->data_offset);
    host->flags = be32toh(be->flags);
    host->header_crc32 = be32toh(be->header_crc32);
    host->original_size = be32toh(be->original_size);
}

// 将主机字节序的RSDataChunkInfo转换为大端字节序（用于写入）
void rs_data_chunk_info_host_to_be(const RSDataChunkInfo* host, RSDataChunkInfo* be) {
    be->block_index = htobe64(host->block_index);
    be->offset = htobe32(host->offset);
    be->size = htobe32(host->size);
    be->crc32 = htobe32(host->crc32);
}

// 将大端字节序的RSDataChunkInfo转换为主机字节序（用于读取）
void rs_data_chunk_info_be_to_host(const RSDataChunkInfo* be, RSDataChunkInfo* host) {
    host->block_index = be64toh(be->block_index);
    host->offset = be32toh(be->offset);
    host->size = be32toh(be->size);
    host->crc32 = be32toh(be->crc32);
}

// 将主机字节序的RSBlockHeader转换为大端字节序（用于写入）
void rs_block_header_host_to_be(const RSBlockHeader* host, RSBlockHeader* be) {
    be->chunk_count = htobe32(host->chunk_count);
    be->chunk_info_size = htobe32(host->chunk_info_size);
    be->data_size = htobe32(host->data_size);
}

// 将大端字节序的RSBlockHeader转换为主机字节序（用于读取）
void rs_block_header_be_to_host(const RSBlockHeader* be, RSBlockHeader* host) {
    host->chunk_count = be32toh(be->chunk_count);
    host->chunk_info_size = be32toh(be->chunk_info_size);
    host->data_size = be32toh(be->data_size);
}

size_t volume_write(VolumeContext* vol, const void* ptr, size_t size, int next_volume_if_needed);

// 统一的写入函数（支持分卷和普通文件）
size_t archive_write(const void* ptr, size_t size, int next_volume_if_needed,int is_write_rs) {
    if (!g_vol_ctx || !g_vol_ctx->is_open) {
        printf("Error: Archive not open for writing\n");
        return 0;
    }

    if (!is_write_rs && g_rs_enabled && g_group_ctx) {
        int ret = write_to_data_block(g_group_ctx, g_group_ctx->current_block_index, ptr, (uint32_t)size);
        if (ret < 0) {
            printf("Error: Failed to buffer data for RS group (error %d)\n", ret);
            g_error_count++;
            return 0;
        }
    }

    if (g_vol_ctx->is_multi_volume) {
        // 多分卷模式
        return volume_write(g_vol_ctx, ptr, size, next_volume_if_needed);
    }
    else {
        // 单文件模式
        size_t written = fwrite(ptr, 1, size, g_vol_ctx->current_file);
        g_vol_ctx->current_pos += written;
        g_vol_ctx->total_written += written;
        return written;
    }
}

// 统一的读取函数（支持分卷和普通文件）
size_t archive_read(void* ptr, size_t size) {
    if (!g_vol_read_ctx || !g_vol_read_ctx->is_open) {
        printf("Error: Archive not open for reading\n");
        return 0;
    }

    return fread(ptr, 1, size, g_vol_read_ctx->file);
}

// 统一的定位函数（支持分卷和普通文件）
int archive_seek(long long offset, int origin) {
    if (!g_vol_read_ctx || !g_vol_read_ctx->is_open) {
        printf("Error: Archive not open for reading\n");
        return -1;
    }

    return _fseeki64(g_vol_read_ctx->file, offset, origin);
}

// 统一的获取位置函数（支持分卷和普通文件）
long long archive_tell(void) {
    if (!g_vol_read_ctx || !g_vol_read_ctx->is_open) {
        printf("Error: Archive not open for reading\n");
        return -1;
    }

    return _ftelli64(g_vol_read_ctx->file);
}

// 写入CRC32（自动转换字节序）
size_t write_crc32(uint32_t crc,int is_write_rs) {
    uint32_t crc_be = htobe32(crc);
    size_t size = archive_write(&crc_be, sizeof(uint32_t), 0, is_write_rs);
    if (!is_write_rs && g_rs_enabled && g_group_ctx && g_group_ctx->total_size >= g_rs_group_size) {
        //print_data_group_context(g_group_ctx);
        //print_reassembled_info(split_info);
        printf("Writing RS data group %llu\n", g_current_block_group_index);
        if (rs_group_reassemble_and_write(g_group_ctx, g_rs_parity_shards, g_current_block_group_index, g_rs_data_shards) < 0) {
            printf("Error: Writing RS data group %llu failed\n", g_current_block_group_index);
            g_error_count++;
        }

        reset_data_group_context(g_group_ctx);
        g_current_block_group_index++;
    }
    return size;
}

// 读取CRC32（自动转换字节序）
int read_crc32(uint32_t* crc, uint32_t* raw_data) {
    *crc = 0;
    uint32_t crc_be;
    size_t read = archive_read(&crc_be, sizeof(uint32_t));
    if (read != sizeof(uint32_t)) return 0;
    *crc = be32toh(crc_be);
    if(raw_data)
        *raw_data = crc_be;
    return 1;
}

// 写入整个BlockHeader（自动转换字节序）
size_t write_block_header(BlockHeader* header,int is_write_rs) {
    BlockHeader be_header;
    header->block_id = get_next_block_index();
    header->block_group_id = g_current_block_group_index;

    if (!is_write_rs && g_rs_enabled && g_group_ctx) {
        int ret = init_data_block(g_group_ctx, header->block_id, header->section_size + sizeof(BlockHeader) + CRC32_SIZE);
        if (ret < 0) {
            printf("Error: Failed to allocate RS buffer for block %llu (error %d)\n",
                (unsigned long long)header->block_id, ret);
            g_error_count++;
            return 0;
        }
    }
    header_host_to_be(header, &be_header);
    uint32_t crc = crc32_calc(&be_header, sizeof(BlockHeader) - 4);
    be_header.header_crc32 = htobe32(crc);
    header->header_crc32 = crc;

    return archive_write(&be_header, sizeof(BlockHeader), 1, is_write_rs);
}

// 读取整个BlockHeader（自动转换字节序）
int read_block_header(BlockHeader* header, BlockHeader* raw_header) {
    BlockHeader be_header;
    size_t read = archive_read(&be_header, sizeof(BlockHeader));
    if (read != sizeof(BlockHeader)) return 0;
    // 计算header CRC时不包括header_crc32字段
    uint32_t calc_header_crc32 = crc32_calc(&be_header, sizeof(BlockHeader) - 4);
    uint32_t crc = be32toh(be_header.header_crc32);
    if (crc != calc_header_crc32) {
        printf("Error: Header crc32 mismatch (stored: 0x%08x calc: 0x%08x)\n",
            crc, calc_header_crc32);
        return 0;
    }
    header_be_to_host(&be_header, header);
    if (raw_header) {
        memcpy(raw_header, &be_header, sizeof(BlockHeader));
    }
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

// ZSTD压缩函数（支持字典）
uint8_t* compress_zstd_with_dict(const uint8_t* data, size_t data_len,
    size_t* compressed_len, int level,
    int* used_dict, uint32_t* dict_id) {
    *used_dict = 0;
    *dict_id = 0;

    // 获取最大压缩后大小
    size_t max_compressed_size = ZSTD_compressBound(data_len);

    // 如果使用字典，需要额外空间存储DictDataHeader
    if (g_dict_ctx && g_dict_ctx->is_loaded && g_dict_ctx->cdict) {
        max_compressed_size += sizeof(DictDataHeader);
    }

    uint8_t* compressed = (uint8_t*)malloc(max_compressed_size);
    if (!compressed) {
        printf("Error: Failed to allocate compression buffer\n");
        return NULL;
    }

    // 尝试使用字典压缩
    if (g_dict_ctx && g_dict_ctx->is_loaded && g_dict_ctx->cctx && g_dict_ctx->cdict) {
        // 使用字典压缩
        size_t dict_compressed_len = ZSTD_compress_usingCDict(
            g_dict_ctx->cctx,
            compressed + sizeof(DictDataHeader),
            max_compressed_size - sizeof(DictDataHeader),
            data, data_len,
            g_dict_ctx->cdict
        );

        if (!ZSTD_isError(dict_compressed_len)) {
            // 字典压缩成功，添加DictDataHeader
            DictDataHeader dict_header;
            dict_header.dict_id = htobe32(g_dict_ctx->dict_id);
            dict_header.data_size = htobe32((uint32_t)data_len);
            memcpy(compressed, &dict_header, sizeof(DictDataHeader));

            *compressed_len = dict_compressed_len + sizeof(DictDataHeader);
            *used_dict = 1;
            *dict_id = g_dict_ctx->dict_id;
            return compressed;
        }
        else {
            // 字典压缩失败，回退到普通压缩
            printf("Warning: Dictionary compression failed, falling back to normal: %s\n",
                ZSTD_getErrorName(dict_compressed_len));
        }
    }

    // 普通压缩（需要创建临时上下文）
    ZSTD_CCtx* cctx = ZSTD_createCCtx();
    if (!cctx) {
        printf("Error: Failed to create compression context\n");
        free(compressed);
        return NULL;
    }

    *compressed_len = ZSTD_compressCCtx(cctx, compressed, max_compressed_size, data, data_len, level);
    ZSTD_freeCCtx(cctx);

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

// ZSTD解压缩函数（支持字典）
uint8_t* decompress_zstd_with_dict(const uint8_t* compressed_data, size_t compressed_len,
    size_t expected_original_len, int has_dict_flag) {
    uint8_t* decompressed = NULL;
    size_t original_len = expected_original_len;
    const uint8_t* actual_compressed_data = compressed_data;
    size_t actual_compressed_len = compressed_len;
    int used_dict = 0;
    uint32_t stored_dict_id = 0;

    // 检查是否有字典压缩标志
    if (has_dict_flag) {
        if (compressed_len < sizeof(DictDataHeader)) {
            printf("Error: Invalid dictionary compressed data (too small)\n");
            return NULL;
        }

        DictDataHeader dict_header;
        memcpy(&dict_header, compressed_data, sizeof(DictDataHeader));
        stored_dict_id = be32toh(dict_header.dict_id);
        original_len = be32toh(dict_header.data_size);

        actual_compressed_data = compressed_data + sizeof(DictDataHeader);
        actual_compressed_len = compressed_len - sizeof(DictDataHeader);

        used_dict = 1;

        // 验证字典是否加载
        if (!g_dict_ctx || !g_dict_ctx->is_loaded || !g_dict_ctx->ddict || !g_dict_ctx->dctx) {
            printf("Error: Dictionary required for decompression (dict_id: 0x%08x) but not loaded\n",
                stored_dict_id);
            return NULL;
        }

        // 验证字典ID
        if (g_dict_ctx->dict_id != stored_dict_id) {
            printf("Warning: Dictionary ID mismatch (loaded: 0x%08x, expected: 0x%08x), attempting decompression anyway\n",
                g_dict_ctx->dict_id, stored_dict_id);
        }
    }

    // 分配解压缓冲区
    decompressed = (uint8_t*)malloc(original_len);
    if (!decompressed) {
        printf("Error: Failed to allocate decompression buffer\n");
        return NULL;
    }

    size_t result;

    if (used_dict) {
        // 使用字典解压（复用上下文字典）
        result = ZSTD_decompress_usingDDict(g_dict_ctx->dctx, decompressed, original_len,
            actual_compressed_data, actual_compressed_len,
            g_dict_ctx->ddict);

        if (ZSTD_isError(result)) {
            printf("Error: Dictionary decompression failed: %s\n", ZSTD_getErrorName(result));
            free(decompressed);
            return NULL;
        }
    }
    else {
        // 普通解压（创建临时上下文）
        ZSTD_DCtx* dctx = ZSTD_createDCtx();
        if (!dctx) {
            printf("Error: Failed to create decompression context\n");
            free(decompressed);
            return NULL;
        }

        result = ZSTD_decompressDCtx(dctx, decompressed, original_len,
            compressed_data, compressed_len);
        ZSTD_freeDCtx(dctx);

        if (ZSTD_isError(result)) {
            printf("Error: ZSTD decompression failed: %s\n", ZSTD_getErrorName(result));
            free(decompressed);
            return NULL;
        }
    }

    if (result != original_len) {
        printf("Error: Decompressed size mismatch: expected %zu, got %zu\n", original_len, result);
        free(decompressed);
        return NULL;
    }

    return decompressed;
}

char* dirname(char* path) {
    static char result[PATH_LEN_FOR_PROC];
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
    char norm_full[PATH_LEN_FOR_PROC];
    char norm_root[PATH_LEN_FOR_PROC];

    strncpy(norm_full, full_path, PATH_LEN_FOR_PROC - 1);
    strncpy(norm_root, root_path, PATH_LEN_FOR_PROC - 1);
    norm_full[PATH_LEN_FOR_PROC - 1] = '\0';
    norm_root[PATH_LEN_FOR_PROC - 1] = '\0';

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
    if (stat64_utf8(filename, &st) == 0) {
        filesize = st.st_size;
    }
    return filesize;
}

// 检查路径是否为目录
int is_directory(const char* path) {
    struct __stat64 st;
    if (stat64_utf8(path, &st) == 0) {
        return (st.st_mode & _S_IFDIR) != 0;
    }
    return 0;
}

// 解析size参数（支持K、M、G、T后缀）
uint64_t parse_size(const char* size_str) {
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
        case 'T':
        case 't':
            size *= 1024LL * 1024 * 1024 * 1024;
            break;
        default:
            printf("Warning: Unknown size suffix '%c', using as bytes\n", *endptr);
            break;
        }
    }

    return size;
}

// 解析section size参数
uint32_t parse_section_size(const char* size_str) {
    uint64_t size = parse_size(size_str);

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

// 解析rs size参数
uint64_t parse_rs_group_size(const char* size_str) {
    uint64_t size = parse_size(size_str);

    // 检查范围
    if (size < MIN_RS_GROUP_SIZE) {
        printf("Warning: RS group size too small (%llu bytes), using minimum %d bytes\n",
            size, MIN_RS_GROUP_SIZE);
        size = MIN_RS_GROUP_SIZE;
    }
    else if (size > MAX_RS_GROUP_SIZE) {
        printf("Warning: RS group size too large (%llu bytes), using maximum %llu bytes\n",
            (unsigned long long)size, (unsigned long long)MAX_RS_GROUP_SIZE);
        size = MAX_RS_GROUP_SIZE;
    }
    return size;
}


// 解析分卷大小参数
uint64_t parse_volume_size(const char* size_str) {
    uint64_t size = parse_size(size_str);

    // 检查范围
    if (size < MIN_VOLUME_SIZE && size > 0) {
        printf("Warning: Volume size too small (%llu bytes), using minimum %d MB\n",
            size, MIN_VOLUME_SIZE / (1024 * 1024));
        size = MIN_VOLUME_SIZE;
    }
    else if (size > MAX_VOLUME_SIZE) {
        printf("Warning: Volume size too large (%llu bytes), using maximum 4TB\n",
            size);
        size = MAX_VOLUME_SIZE;
    }

    return size;
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

// 生成分卷文件名
void get_volume_filename(const char* base_name, uint64_t volume_num, char* out_name, size_t out_size) {
    // 移除可能存在的.lxar后缀
    char temp_base[512];
    strncpy(temp_base, base_name, sizeof(temp_base) - 1);
    temp_base[sizeof(temp_base) - 1] = '\0';

    char* dot = strrchr(temp_base, '.');
    if (dot && _stricmp(dot, ".lxar") == 0) {
        *dot = '\0';
    }

    // 根据分卷编号决定格式
    if (volume_num < 1000) {
        snprintf(out_name, out_size, "%s.%03d.lxar", temp_base, (int)volume_num);
    }
    else {
        // 对于超过999的分卷，使用更灵活的格式
        snprintf(out_name, out_size, "%s.%llu.lxar", temp_base, (unsigned long long)volume_num);
    }
}

// 解析分卷文件名，提取基础名和分卷编号
int parse_volume_filename(const char* filename, char* base_name, size_t base_size, uint64_t* volume_num) {
    char temp[512];
    strncpy(temp, filename, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    // 查找最后一个.lxar
    char* last_dot = strrchr(temp, '.');
    if (!last_dot || _stricmp(last_dot, ".lxar") != 0) {
        return -1;
    }
    *last_dot = '\0';  // 移除.lxar

    // 查找最后一个点（分卷编号前的点）
    char* vol_dot = strrchr(temp, '.');
    if (!vol_dot) {
        return -1;
    }

    // 尝试解析分卷编号
    char* vol_str = vol_dot + 1;
    char* endptr;
    unsigned long long num = strtoull(vol_str, &endptr, 10);

    if (*endptr != '\0' || num == 0) {
        return -1;
    }

    // 成功解析分卷编号
    *vol_dot = '\0';  // 移除分卷编号部分
    strncpy(base_name, temp, base_size);
    *volume_num = num;
    return 0;
}

// 将Unix时间戳转换为可读的日期时间字符串
void format_datetime(uint64_t timestamp, char* buffer, size_t buffer_size) {
    time_t t = (time_t)timestamp;
    struct tm* tm_info = localtime(&t);
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Windows下遍历目录的函数
void walk_directory(const char* path, void (*file_callback)(const char*), void (*dir_callback)(const char*)) {
    WCHAR search_path[PATH_LEN_FOR_PROC];
    WCHAR* wchar_path = utf8_to_utf16(path);
    if (wchar_path == NULL) {
        printf("Error: path UTF8 to UTF16 failed\n");
        g_error_count++;
        return;
    }
    swprintf(search_path, PATH_LEN_FOR_PROC, L"%s\\*", wchar_path);
    free(wchar_path);

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(search_path, &findData);
    char* utf8_filename = NULL;
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open directory %s (error: %lu)\n", path, GetLastError());
        g_error_count++;
        return;
    }

    do {
        if (utf8_filename) {
            free(utf8_filename);
        }
        utf8_filename = utf16_to_utf8(findData.cFileName);
        if (utf8_filename == NULL) {
            printf("Error: UTF16 to UTF8 failed\n");
            g_error_count++;
            break;
        }
        if (strcmp(utf8_filename, ".") != 0 &&
            strcmp(utf8_filename, "..") != 0) {

            char full_path[PATH_LEN_FOR_PROC];
            snprintf(full_path, PATH_LEN_FOR_PROC, "%s\\%s", path, utf8_filename);


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
    } while (FindNextFileW(hFind, &findData));

    DWORD error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        printf("Error: Error while enumerating directory %s (error: %lu)\n", path, error);
        g_error_count++;
    }

    FindClose(hFind);
    if (utf8_filename) {
        free(utf8_filename);
    }
}

// Windows下创建目录（支持指定根路径）
int create_directories_with_root(const char* root_path, const char* rel_path) {
    char full_path[PATH_LEN_FOR_PROC];

    if (root_path && strlen(root_path) > 0) {
        // 规范化根路径
        char norm_root[PATH_LEN_FOR_PROC];
        strncpy(norm_root, root_path, PATH_LEN_FOR_PROC - 1);
        norm_root[PATH_LEN_FOR_PROC - 1] = '\0';

        // 去除根路径末尾的斜杠
        size_t root_len = strlen(norm_root);
        while (root_len > 0 && (norm_root[root_len - 1] == '\\' || norm_root[root_len - 1] == '/')) {
            norm_root[--root_len] = '\0';
        }

        // 构建完整路径
        snprintf(full_path, PATH_LEN_FOR_PROC, "%s\\%s", norm_root, rel_path);
    }
    else {
        strncpy(full_path, rel_path, PATH_LEN_FOR_PROC - 1);
        full_path[PATH_LEN_FOR_PROC - 1] = '\0';
    }

    // 将正斜杠转换为反斜杠（Windows）
    for (int i = 0; full_path[i]; i++) {
        if (full_path[i] == '/') full_path[i] = '\\';
    }

    // 创建目录
    char tmp[PATH_LEN_FOR_PROC];
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
            mkdir_utf8(tmp);
            *p = '\\';
        }
    }
    return mkdir_utf8(tmp);
}

// 创建目录（兼容旧代码）
int create_directories(const char* path) {
    return create_directories_with_root(NULL, path);
}

// 构建输出文件路径
void build_output_path(const char* output_root, const char* rel_path, char* out_path, size_t max_len) {
    if (output_root && strlen(output_root) > 0) {
        // 规范化输出根路径
        char norm_root[PATH_LEN_FOR_PROC];
        strncpy(norm_root, output_root, PATH_LEN_FOR_PROC - 1);
        norm_root[PATH_LEN_FOR_PROC - 1] = '\0';

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

// 分卷文件管理函数 - 打开下一个分卷
int volume_open_next(VolumeContext* vol) {
    if (vol->is_multi_volume && vol->current_volume >= MAX_VOLUME_NUMBER) {
        printf("Error: Maximum volume number (%d) exceeded!\n", MAX_VOLUME_NUMBER);
        return -1;
    }

    if (vol->current_file) {
        fclose(vol->current_file);
        vol->current_file = NULL;
    }

    vol->current_volume++;

    char vol_name[512];
    if (vol->is_multi_volume) {
        get_volume_filename(vol->base_name, vol->current_volume, vol_name, sizeof(vol_name));
        printf("Creating volume: %s\n", vol_name);
    }
    else {
        // 单文件模式，直接使用基础名
        strncpy(vol_name, vol->base_name, sizeof(vol_name) - 1);
        vol_name[sizeof(vol_name) - 1] = '\0';
        printf("Creating archive: %s\n", vol_name);
    }

    vol->current_file = fopen_utf8(vol_name, "wb");
    if (!vol->current_file) {
        printf("Error: Cannot create volume file: %s\n", vol_name);
        return -1;
    }

    vol->current_pos = 0;
    vol->is_open = 1;
    return 0;
}

// 初始化分卷写入上下文
int volume_init(VolumeContext* vol, const char* base_name, uint64_t volume_size) {
    memset(vol, 0, sizeof(VolumeContext));
    strncpy(vol->base_name, base_name, sizeof(vol->base_name) - 1);
    vol->base_name[sizeof(vol->base_name) - 1] = '\0';

    vol->volume_size = volume_size;
    vol->current_volume = 0;
    vol->current_pos = 0;
    vol->total_written = 0;
    vol->current_file = NULL;
    vol->is_open = 0;
    vol->is_multi_volume = (volume_size > 0);

    // 打开第一个分卷
    return volume_open_next(vol);
}

// 分卷写入数据
size_t volume_write(VolumeContext* vol, const void* ptr, size_t size, int next_volume_if_needed) {
    if (!vol->is_open || !vol->current_file) {
        printf("Error: Volume not open for writing\n");
        return 0;
    }
    int ret = 0;
    const uint8_t* data = (const uint8_t*)ptr;

    if (next_volume_if_needed && vol->current_pos >= vol->volume_size) {
        ret = volume_open_next(vol);
        if (ret != 0)
            return 0;
        vol->current_pos = 0;
    }

    size_t write_size = size;
    size_t written = fwrite(data, 1, write_size, vol->current_file);
    vol->current_pos += written;
    vol->total_written += written;
    return written;
}

// 关闭分卷
void volume_close(VolumeContext* vol) {
    if (vol->current_file) {
        fclose(vol->current_file);
        vol->current_file = NULL;
    }
    vol->is_open = 0;
}

// 分卷读取初始化
int volume_read_init(VolumeReadContext* ctx, const char* archive_name) {
    memset(ctx, 0, sizeof(VolumeReadContext));

    // 解析文件名，获取基础名和分卷编号
    if (parse_volume_filename(archive_name, ctx->base_name, sizeof(ctx->base_name), &ctx->current_volume) != 0) {
        // 解析失败，直接使用原文件名
        strncpy(ctx->base_name, archive_name, sizeof(ctx->base_name) - 1);
        ctx->base_name[sizeof(ctx->base_name) - 1] = '\0';
        ctx->current_volume = 1;
        ctx->is_multi_volume = 0;
    }
    else {
        ctx->is_multi_volume = 1;
    }

    strncpy(ctx->current_file, archive_name, sizeof(ctx->current_file) - 1);
    ctx->current_file[sizeof(ctx->current_file) - 1] = '\0';

    // 尝试打开文件
    ctx->file = fopen_utf8(archive_name, "rb");
    if (ctx->file) {
        ctx->is_open = 1;
        ctx->file_size = get_file_size(archive_name);
        printf("Opened: %s", archive_name);
        if (ctx->is_multi_volume) {
            printf(" (volume %llu of multi-volume archive, base: %s)",
                (unsigned long long)ctx->current_volume, ctx->base_name);
        }
        printf("\n");
        return 0;
    }

    printf("Error: Cannot open archive file: %s\n", archive_name);
    return -1;
}

// 分卷读取 - 打开下一个分卷
int volume_read_next(VolumeReadContext* ctx) {
    if (!ctx->is_multi_volume) {
        return -1;  // 不是多分卷模式，没有下一个
    }

    if (ctx->file) {
        fclose(ctx->file);
        ctx->file = NULL;
    }

    ctx->current_volume++;

    // 构建下一个分卷文件名
    char next_vol[512];
    get_volume_filename(ctx->base_name, ctx->current_volume, next_vol, sizeof(next_vol));

    ctx->file = fopen_utf8(next_vol, "rb");
    if (!ctx->file) {
        return -1;  // 没有更多分卷
    }

    ctx->file_size = get_file_size(next_vol);
    printf("Opening next volume: %s (volume %llu)\n", next_vol, (unsigned long long)ctx->current_volume);
    return 0;
}

// 关闭分卷读取
void volume_read_close(VolumeReadContext* ctx) {
    if (ctx->file) {
        fclose(ctx->file);
        ctx->file = NULL;
    }
    ctx->is_open = 0;
}

// 验证块头的有效性
int validate_block_header(BlockHeader* header, long long found_pos, long long start_pos, uint64_t* block_num) {
    if (header->magic != MAGIC_NUMBER_FILE && header->magic != MAGIC_NUMBER_DIR) {
        printf("Error: Invalid magic number 0x%08x at position %llu\n",
            header->magic, (unsigned long long)archive_tell() - sizeof(BlockHeader));
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

static int archive_block_index_compare(const void* left, const void* right) {
    const ArchiveBlockIndexEntry* a = (const ArchiveBlockIndexEntry*)left;
    const ArchiveBlockIndexEntry* b = (const ArchiveBlockIndexEntry*)right;
    if (a->block_id < b->block_id) return -1;
    if (a->block_id > b->block_id) return 1;
    if (a->volume_number < b->volume_number) return -1;
    if (a->volume_number > b->volume_number) return 1;
    return a->offset < b->offset ? -1 : (a->offset > b->offset ? 1 : 0);
}

static int archive_block_index_add(ArchiveBlockIndex* index,
    uint64_t block_id, uint64_t volume_number, long long offset) {
    if (index->count == index->capacity) {
        size_t new_capacity = index->capacity ? index->capacity * 2 : 1024;
        ArchiveBlockIndexEntry* entries = (ArchiveBlockIndexEntry*)realloc(
            index->entries, new_capacity * sizeof(*entries));
        if (!entries) return -1;
        index->entries = entries;
        index->capacity = new_capacity;
    }
    index->entries[index->count].block_id = block_id;
    index->entries[index->count].volume_number = volume_number;
    index->entries[index->count].offset = offset;
    index->count++;
    return 0;
}

static int archive_index_scan_volume(FILE* file, long long file_size,
    uint64_t volume_number, ArchiveBlockIndex* index) {
    long long start_pos = 0;
    while (1) {
        long long pos = find_next_magic(file, start_pos, file_size);
        if (pos < 0) break;
        if (_fseeki64(file, pos, SEEK_SET) != 0) break;

        BlockHeader raw_header;
        BlockHeader header;
        if (fread(&raw_header, 1, sizeof(raw_header), file) != sizeof(raw_header)) {
            start_pos = pos + 1;
            continue;
        }
        uint32_t stored_header_crc = be32toh(raw_header.header_crc32);
        if (crc32_calc(&raw_header, sizeof(raw_header) - sizeof(uint32_t)) != stored_header_crc) {
            start_pos = pos + 1;
            continue;
        }
        header_be_to_host(&raw_header, &header);
        if (header.magic != MAGIC_NUMBER_FILE && header.magic != MAGIC_NUMBER_DIR) {
            start_pos = pos + 1;
            continue;
        }

        uint8_t data_buffer[64 * 1024];
        uint64_t remaining = header.section_size;
        CRC32_Context crc_ctx;
        crc32_init(&crc_ctx);
        int data_valid = 1;
        while (remaining > 0) {
            size_t read_size = remaining < sizeof(data_buffer) ?
                (size_t)remaining : sizeof(data_buffer);
            if (fread(data_buffer, 1, read_size, file) != read_size) {
                data_valid = 0;
                break;
            }
            crc32_update(&crc_ctx, data_buffer, read_size);
            remaining -= read_size;
        }
        if (!data_valid) {
            start_pos = pos + (long long)sizeof(BlockHeader);
            continue;
        }
        uint32_t raw_crc = 0;
        if (fread(&raw_crc, 1, sizeof(raw_crc), file) != sizeof(raw_crc)) {
            start_pos = pos + (long long)sizeof(BlockHeader);
            continue;
        }
        uint32_t stored_crc = be32toh(raw_crc);
        uint32_t calculated_crc = crc32_final(&crc_ctx);
        int crc_valid = header.magic == MAGIC_NUMBER_DIR ? stored_crc == 0 :
            (header.section_size == 0 ? stored_crc == 0 : calculated_crc == stored_crc);
        /* Keep blocks with an intact header and complete physical payload even
         * when their data CRC fails. RS recovery can still use unaffected
         * chunks inside the block. */
        if (archive_block_index_add(index, header.block_id, volume_number, pos) != 0) {
            return -1;
        }
        start_pos = crc_valid ? _ftelli64(file) :
            pos + (long long)sizeof(BlockHeader);
    }
    return 0;
}

static int copy_file_range(FILE* source, FILE* target, long long offset, uint64_t size) {
    uint8_t buffer[64 * 1024];
    if (_fseeki64(source, offset, SEEK_SET) != 0) return -1;
    while (size > 0) {
        size_t want = size < sizeof(buffer) ? (size_t)size : sizeof(buffer);
        size_t got = fread(buffer, 1, want, source);
        if (got != want || fwrite(buffer, 1, got, target) != got) return -1;
        size -= got;
    }
    return 0;
}

static int create_indexed_archive(const char* archive_name, const char* indexed_name) {
    VolumeReadContext scan_ctx;
    ArchiveBlockIndex index = { 0 };
    if (volume_read_init(&scan_ctx, archive_name) != 0) return -1;

    do {
        if (archive_index_scan_volume(scan_ctx.file, scan_ctx.file_size,
            scan_ctx.current_volume, &index) != 0) {
            volume_read_close(&scan_ctx);
            free(index.entries);
            return -1;
        }
    } while (volume_read_next(&scan_ctx) == 0);
    volume_read_close(&scan_ctx);

    qsort(index.entries, index.count, sizeof(*index.entries), archive_block_index_compare);
    FILE* output = fopen_utf8(indexed_name, "wb");
    if (!output) {
        free(index.entries);
        return -1;
    }

    char base_name[512];
    uint64_t first_volume = 1;
    int multi_volume = parse_volume_filename(archive_name, base_name, sizeof(base_name), &first_volume) == 0;
    FILE* source = NULL;
    uint64_t source_volume = UINT64_MAX;
    int result = -1;
    for (size_t i = 0; i < index.count; i++) {
        uint64_t indexed_volume = index.entries[i].volume_number;
        if (!source || source_volume != indexed_volume) {
            char source_name[512];
            if (source) {
                fclose(source);
                source = NULL;
            }
            if (multi_volume) {
                get_volume_filename(base_name, indexed_volume,
                    source_name, sizeof(source_name));
            }
            else {
                strncpy(source_name, archive_name, sizeof(source_name) - 1);
                source_name[sizeof(source_name) - 1] = '\0';
            }
            source = fopen_utf8(source_name, "rb");
            if (!source) goto cleanup_indexed_archive;
            source_volume = indexed_volume;
        }
        if (_fseeki64(source, index.entries[i].offset, SEEK_SET) != 0) {
            goto cleanup_indexed_archive;
        }
        BlockHeader raw_header;
        if (fread(&raw_header, 1, sizeof(raw_header), source) != sizeof(raw_header)) {
            goto cleanup_indexed_archive;
        }
        BlockHeader header;
        header_be_to_host(&raw_header, &header);
        uint64_t block_size = sizeof(BlockHeader) + (uint64_t)header.section_size + CRC32_SIZE;
        if (copy_file_range(source, output, index.entries[i].offset, block_size) != 0) {
            goto cleanup_indexed_archive;
        }
    }
    result = 0;

cleanup_indexed_archive:
    if (source) fclose(source);
    fclose(output);
    free(index.entries);
    if (result == 0) {
    printf("Indexed %zu header-valid blocks and sorted them by block_id\n", index.count);
    }
    else {
        remove_utf8(indexed_name);
    }
    return result;
}

static int extract_archive_indexed(const char* archive_name, char** files, int file_count,
    int repair) {
    char indexed_name[PATH_LEN_FOR_PROC];
    snprintf(indexed_name, sizeof(indexed_name), "%s.indexed.tmp", archive_name);
    if (create_indexed_archive(archive_name, indexed_name) != 0) {
        printf("Error: Failed to build archive block index\n");
        return -1;
    }
    int result = repair ? extract_archive_with_repair(indexed_name, files, file_count) :
        extract_archive(indexed_name, files, file_count);
    if (remove_utf8(indexed_name) != 0) {
        printf("Warning: Failed to remove indexed temporary archive: %s\n", indexed_name);
    }
    return result;
}

// 扫描并定位下一个magic number
long long find_next_magic(FILE* file, long long start_pos, long long file_size) {
    unsigned char byte;
    long long pos = start_pos;
    uint32_t magic_accumulator = 0;

    if (start_pos >= file_size - 4) {
        return -1;
    }

    _fseeki64(file, pos, SEEK_SET);

    while (fread(&byte, 1, 1, file) == 1) {
        magic_accumulator = ((magic_accumulator << 8) & 0xFFFFFF00) | byte;

        if (magic_accumulator == MAGIC_NUMBER_FILE || magic_accumulator == MAGIC_NUMBER_DIR) {
            long long found_pos = pos - 3;
            _fseeki64(file, found_pos, SEEK_SET);
            return found_pos;
        }

        pos++;
    }

    return -1;
}

// 处理目录的回调函数
void process_directory(const char* dirpath) {
    // 获取相对于输入根目录的路径
    char relative_path[MAX_PATH_LEN] = { 0 };

    if (get_relative_path(dirpath, g_input_root_path, relative_path, sizeof(relative_path)) != 0) {
        printf("Warning: Path issue for directory %s\n", dirpath);
        g_warning_count++;
        // 继续处理
    }

    // 确保目录名以/结尾
    size_t len = strlen(relative_path);
    if (len > 0 && relative_path[len - 1] != '/') {
        if (len < MAX_PATH_LEN - 1) {
            relative_path[len] = '/';
            relative_path[len + 1] = '\0';
        }
    }
    relative_path[MAX_PATH_LEN - 1] = '\0';

    // 获取目录信息
    struct __stat64 st;
    if (stat64_utf8(dirpath, &st) != 0) {
        printf("Error: Cannot get directory stat %s\n", dirpath);
        g_error_count++;
        return;
    }

    printf("Archiving directory: %s\n", relative_path);

    // 创建目录块
    BlockHeader header = { 0 };
    header.magic = MAGIC_NUMBER_DIR;
    strncpy(header.filename, relative_path, MAX_PATH_LEN - 1);
    header.filename[MAX_PATH_LEN - 1] = '\0';
    header.mtime = st.st_mtime;
    header.total_size = 0;
    header.section_id = 0;
    header.section_size = 0;
    header.total_section_count = 0;
    header.data_offset = 0;
    header.flags = 0;
    header.original_size = 0;

    // 写入块头
    if (write_block_header(&header,0) != sizeof(BlockHeader)) {
        printf("Error: Failed to write directory header for %s\n", relative_path);
        g_error_count++;
        return;
    }

    // 目录没有数据块，直接写入CRC32（全0）
    if (write_crc32(0,0) != sizeof(uint32_t)) {
        printf("Error: Failed to write CRC for directory %s\n", relative_path);
        g_error_count++;
        return;
    }

    total_dirs_processed++;
}

// 处理单个文件的回调函数
void process_file(const char* filepath) {
    FILE* infile = fopen_utf8(filepath, "rb");
    if (!infile) {
        printf("Error: Cannot open file %s\n", filepath);
        g_error_count++;
        return;
    }

    // 获取文件信息
    struct __stat64 st;
    if (stat64_utf8(filepath, &st) != 0) {
        printf("Error: Cannot get file stat %s\n", filepath);
        fclose(infile);
        g_error_count++;
        return;
    }

    // 获取相对于输入根目录的路径
    char relative_path[MAX_PATH_LEN] = { 0 };
    if (g_single_file_input) {
        strncpy(relative_path, get_last_path_component(filepath), sizeof(relative_path) - 1);
        relative_path[sizeof(relative_path) - 1] = '\0';
    }
    else if (get_relative_path(filepath, g_input_root_path, relative_path, sizeof(relative_path)) != 0) {
        printf("Warning: Path issue for %s\n", filepath);
        g_warning_count++;
        // 继续处理，使用可能不完整的路径
    }
    relative_path[MAX_PATH_LEN - 1] = '\0';

    long long file_size = st.st_size;

    if (file_size == 0) {
        // 处理0字节文件
        printf("Archiving empty file: %s\n", relative_path);

        BlockHeader header = { 0 };
        header.magic = MAGIC_NUMBER_FILE;
        strncpy(header.filename, relative_path, MAX_PATH_LEN - 1);
        header.filename[MAX_PATH_LEN - 1] = '\0';
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

        // 写入块头
        if (write_block_header(&header,0) != sizeof(BlockHeader)) {
            printf("Error: Failed to write file header for %s\n", relative_path);
            fclose(infile);
            g_error_count++;
            return;
        }

        // 空文件没有数据，直接写入CRC32（全0）
        if (write_crc32(0, 0) != sizeof(uint32_t)) {
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
            int used_dict = 0;

            // 压缩数据（如果启用压缩）
            if (g_compression_enabled) {
                uint32_t dict_id = 0;
                size_t zstd_compressed_len;
                uint8_t* compressed_data = compress_zstd_with_dict(
                    original_buffer, section_size,
                    &zstd_compressed_len, g_compression_level,
                    &used_dict, &dict_id
                );

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
            strncpy(header.filename, relative_path, MAX_PATH_LEN - 1);
            header.filename[MAX_PATH_LEN - 1] = '\0';
            header.mtime = st.st_mtime;
            header.total_size = file_size;
            header.section_id = section_id;
            header.section_size = data_to_write_len;  // 加密后的数据大小（如果有加密）
            header.total_section_count = total_section_count;
            header.flags = 0;
            if (g_encryption_enabled) header.flags |= FLAG_ENCRYPTED;
            if (g_compression_enabled && compressed_len > 0) {
                header.flags |= FLAG_COMPRESSED; 
                // 设置字典压缩标志
                if (used_dict) {
                    header.flags |= FLAG_DICT_COMPRESSED;
                }
            }

            header.data_offset = file_offset;
            header.original_size = original_len;  // 保存原始大小用于解压缩

            // 写入块头
            if (write_block_header(&header,0) != sizeof(BlockHeader)) {
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
            if (archive_write(data_to_write, data_to_write_len, 0, 0) != data_to_write_len) {
                printf("Error: Failed to write data for %s section id %llu\n",
                    relative_path, (unsigned long long)section_id);
                free(data_to_write);
                fclose(infile);
                g_error_count++;
                return;
            }

            uint32_t crc = crc32_final(&ctx);

            // 写入CRC32
            if (write_crc32(crc, 0) != sizeof(uint32_t)) {
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

// 创建归档文件（支持分卷）
int create_archive(const char* archive_name, const char* input_path) {
    if(g_rs_enabled) {
        fec_init();
    }
    int ret = 0;
    // 检查输入路径是否存在，并区分单文件和目录输入
    struct __stat64 input_stat;
    if (stat64_utf8(input_path, &input_stat) != 0) {
        printf("Error: Input path does not exist: %s\n", input_path);
        ret = -1;
        goto end;
    }
    g_single_file_input = (input_stat.st_mode & _S_IFDIR) == 0;

    VolumeContext vol_ctx;
    g_vol_ctx = &vol_ctx;  // 设置全局分卷写入上下文指针
    g_group_ctx = init_data_group_context();
    if (g_group_ctx == NULL) {
        ret = -1;
        goto end;
    }
    // 初始化分卷
    if (volume_init(&vol_ctx, archive_name, g_volume_size) != 0) {
        g_vol_ctx = NULL;
        ret = -1;
        goto end;
    }

    // 重置计数器和错误标志
    total_files_processed = 0;
    total_dirs_processed = 0;
    g_error_count = 0;
    g_warning_count = 0;

    // 保存输入根路径供回调函数使用
    static char input_root[PATH_LEN_FOR_PROC];
    strncpy(input_root, input_path, PATH_LEN_FOR_PROC - 1);
    input_root[PATH_LEN_FOR_PROC - 1] = '\0';
    // 去除末尾的斜杠
    size_t root_len = strlen(input_root);
    while (root_len > 0 && (input_root[root_len - 1] == '\\' || input_root[root_len - 1] == '/')) {
        input_root[--root_len] = '\0';
    }
    g_input_root_path = input_root;

    if (g_volume_size > 0) {
        printf("Creating multi-volume archive, base name: %s\n", archive_name);
        printf("Volume size: %llu bytes (%.2f MB, %.2f GB)\n",
            (unsigned long long)g_volume_size,
            g_volume_size / (1024.0 * 1024.0),
            g_volume_size / (1024.0 * 1024.0 * 1024.0));
        printf("Maximum volumes supported: %d\n", MAX_VOLUME_NUMBER);
    }

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

    if (g_single_file_input) {
        process_file(input_path);
    }
    else {
        // Windows下使用自定义目录遍历，先处理目录，再处理文件
        walk_directory(input_path, process_file, process_directory);
    }

    if (g_rs_enabled && g_group_ctx && g_group_ctx->total_size > 0) {
        //print_data_group_context(g_group_ctx);
        //print_reassembled_info(split_info);
        printf("Writing RS data group %llu\n", g_current_block_group_index);
        if (rs_group_reassemble_and_write(g_group_ctx, g_rs_parity_shards, g_current_block_group_index, g_rs_data_shards) < 0) {
            printf("Error: Writing RS data group %llu failed\n", g_current_block_group_index);
            g_error_count++;
        }

        reset_data_group_context(g_group_ctx);
        g_current_block_group_index++;
    }

    // 关闭文件
    volume_close(&vol_ctx);
    g_vol_ctx = NULL;

    // 输出最终统计
    printf("\nArchive creation completed:\n");
    printf("  - Directories: %d\n", total_dirs_processed);
    printf("  - Files: %d (including empty files)\n", total_files_processed);
    printf("  - Total: %d\n", total_files_processed + total_dirs_processed);

    if (g_volume_size > 0) {
        printf("  - Volumes: %llu\n", (unsigned long long)vol_ctx.current_volume);
        printf("  - Total size: %llu bytes (%.2f MB, %.2f GB)\n",
            (unsigned long long)vol_ctx.total_written,
            vol_ctx.total_written / (1024.0 * 1024.0),
            vol_ctx.total_written / (1024.0 * 1024.0 * 1024.0));
    }

    if (g_warning_count > 0) {
        printf("  - Warnings: %d\n", g_warning_count);
    }

    if (g_error_count > 0) {
        printf("  - Errors: %d\n", g_error_count);
        printf("Archive created with errors! Some files may be missing or corrupted.\n");
        ret = -1;
        goto end;
    }
    else {
        printf("Archive created successfully.\n");
    }
end:
    if (g_group_ctx) {
        free_data_group_context(g_group_ctx);
        g_group_ctx = NULL;
    }
    return ret;
}

// 列出归档内容（支持分卷）
int list_archive(const char* archive_name) {
    VolumeReadContext vol_ctx;
    if (volume_read_init(&vol_ctx, archive_name) != 0) {
        return -1;
    }
    g_vol_read_ctx = &vol_ctx;

    BlockHeader header;
    uint64_t total_files = 0;
    uint64_t total_dirs = 0;
    uint64_t total_blocks = 0;
    char current_file[MAX_PATH_LEN] = { 0 };
    long long start_pos = 0;
    long long pos = 0;
    int result;
    char datetime_str[20];

    // 用于跟踪哪些文件已经显示过
    typedef struct {
        char filename[MAX_PATH_LEN];
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

    printf("Archive contents:\n");
    if (vol_ctx.is_multi_volume) {
        printf("Multi-volume archive, base name: %s\n", vol_ctx.base_name);
    }
    printf("%-30s %-20s %-10s %-10s %-12s %s\n", "Name", "Modified Time", "Type", "Size", "Flags", "CRC");
    printf("------------------------------------------------\n");

    long long filesize = vol_ctx.file_size;

    while (1) {
        pos = find_next_magic(vol_ctx.file, start_pos, filesize);
        if (pos == -1) {
            // 尝试下一个分卷
            if (volume_read_next(&vol_ctx) != 0) {
                break;  // 没有更多分卷
            }
            start_pos = 0;
            filesize = vol_ctx.file_size;
            continue;
        }

        if (!read_block_header(&header,NULL)) {
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
            archive_seek(header.section_size, SEEK_CUR);
            read_crc32(&stored_crc,NULL);
        }
        else {
            // 目录或空文件：直接读CRC（位于头之后）
            read_crc32(&stored_crc,NULL);
        }

        // 格式化时间
        format_datetime(header.mtime, datetime_str, sizeof(datetime_str));

        // 构建标志字符串
        char flags_str[32] = "";
        if (header.flags & FLAG_ENCRYPTED) strcat(flags_str, "AES ");
        if (header.flags & FLAG_COMPRESSED) {
            if (strlen(flags_str) > 0) strcat(flags_str, " ");
            if (header.flags & FLAG_DICT_COMPRESSED) {
                strcat(flags_str, "ZSTD+Dict");
            }
            else {
                strcat(flags_str, "ZSTD");
            }
        }
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
                    DisplayedFile* tmp = (DisplayedFile*)realloc(displayed_files,
                        displayed_capacity * sizeof(DisplayedFile));
                    if (!tmp) {
                        printf("Error: Out of memory\n");
                        break;
                    }
                    displayed_files = tmp;
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

        start_pos = archive_tell();
    }

    printf("------------------------------------------------\n");
    printf("Total: %llu directories, %llu files, %llu blocks\n",
        (unsigned long long)total_dirs,
        (unsigned long long)total_files,
        (unsigned long long)total_blocks);

    free(displayed_files);
    volume_read_close(&vol_ctx);
    g_vol_read_ctx = NULL;
    return 0;
}

// 验证归档完整性（支持分卷）
int verify_archive(const char* archive_name) {
    VolumeReadContext vol_ctx;
    if (volume_read_init(&vol_ctx, archive_name) != 0) {
        return -1;
    }
    g_vol_read_ctx = &vol_ctx;

    BlockHeader header;
    uint64_t block_num = 0;
    int corrupted_blocks = 0;
    int missing_first_blocks = 0;
    long long start_pos = 0;
    long long pos = 0;
    char datetime_str[20];

    // 用于跟踪文件信息
    typedef struct {
        char filename[MAX_PATH_LEN];
        uint64_t total_sections;
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
    if (vol_ctx.is_multi_volume) {
        printf("Multi-volume archive detected. Base name: %s\n", vol_ctx.base_name);
    }
    if (g_encryption_enabled) {
        printf("Decryption enabled for verification\n");
    }
    printf("%-30s %-20s %-10s %s\n", "Name", "Modified Time", "Type", "Status");
    printf("------------------------------------------------\n");

    long long filesize = vol_ctx.file_size;

    while (1) {
        pos = find_next_magic(vol_ctx.file, start_pos, filesize);
        if (pos == -1) {
            // 尝试下一个分卷
            if (volume_read_next(&vol_ctx) != 0) {
                break;  // 没有更多分卷
            }
            start_pos = 0;
            filesize = vol_ctx.file_size;
            continue;
        }

        if (!read_block_header(&header,NULL)) {
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
                FileVerifyInfo *tmp = (FileVerifyInfo*)realloc(file_info,
                    file_capacity * sizeof(FileVerifyInfo));
                if (!tmp) {
                    printf("Error: Out of memory\n");
                    break;
                }
                file_info = tmp;
            }

            file_idx = file_count++;
            strcpy(file_info[file_idx].filename, header.filename);
            file_info[file_idx].total_sections = header.total_section_count;
            file_info[file_idx].first_section_id_found = header.section_id;
            file_info[file_idx].last_section_id_found = header.section_id;
            file_info[file_idx].has_section0 = (header.section_id == 0);
            file_info[file_idx].is_corrupted = 0;
            file_info[file_idx].is_encrypted = (header.flags & FLAG_ENCRYPTED) ? 1 : 0;
            file_info[file_idx].is_compressed = (header.flags & FLAG_COMPRESSED) ? 1 : 0;
        }
        else if (file_idx != -1) {
            // 更新现有文件信息
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
            read_crc32(&stored_crc,NULL);
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
                read_crc32(&stored_crc,NULL);
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
                    volume_read_close(&vol_ctx);
                    free(file_info);
                    g_vol_read_ctx = NULL;
                    return -1;
                }

                size_t actual_read = archive_read(data_buffer, header.section_size);
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
                read_crc32(&stored_crc,NULL);
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
                char flags_str[64] = "";
                if (header.flags & FLAG_ENCRYPTED) strcat(flags_str, "encrypted ");
                if (header.flags & FLAG_COMPRESSED) {
                    if (strlen(flags_str) > 0) strcat(flags_str, " ");
                    strcat(flags_str, "compressed(ZSTD)");
                    if (header.flags & FLAG_DICT_COMPRESSED) {
                        strcat(flags_str, "+dict");
                    }
                }

                // 显示section信息
                printf("%-30s %-20s %-10s %s (Block id %llu, Group id %llu, Section id %llu/%llu, Data Offset %llu, Original Size: %u,Section Size: %u, CRC: 0x%08x%s%s)\n",
                    header.filename, datetime_str, "FILE",
                    status,
                    (unsigned long long)header.block_id,
                    (unsigned long long)header.block_group_id,
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

        start_pos = archive_tell();
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
    volume_read_close(&vol_ctx);
    g_vol_read_ctx = NULL;
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


// 用于跟踪当前正在提取的文件
typedef struct {
    char filename[MAX_PATH_LEN];
    FILE* outfile;
    uint64_t expected_size;
    uint64_t current_size;
    uint64_t expected_section_id;
    uint64_t total_sections;
    int is_encrypted;
    int is_compressed;
    int corrupted;
    int found;
    ProgressContext progress;
} ExtractingFile;

static int extracting_file_open(ExtractingFile* file, const BlockHeader* header) {
    char output_file_path[PATH_LEN_FOR_PROC];
    char* dir_path;
    char* dir;

    if (file->outfile) {
        return 0;
    }

    build_output_path(g_output_path, header->filename, output_file_path, sizeof(output_file_path));
    dir_path = _strdup(output_file_path);
    if (!dir_path) {
        return -1;
    }
    dir = dirname(dir_path);
    if (strcmp(dir, ".") != 0 && strcmp(dir, "\\") != 0 && strlen(dir) > 0) {
        create_directories(dir);
    }
    free(dir_path);

    printf("Extracting: %s", header->filename);
    if (header->flags & FLAG_ENCRYPTED) printf(" (encrypted)");
    if (header->flags & FLAG_COMPRESSED) printf(" (compressed)");
    printf("\n");

    file->outfile = fopen_utf8(output_file_path, "wb");
    if (!file->outfile) {
        printf("Error: Cannot create file %s\n", output_file_path);
        return -1;
    }

    file->expected_size = header->total_size;
    file->current_size = 0;
    file->expected_section_id = 0;
    file->total_sections = header->total_section_count;
    file->is_encrypted = (header->flags & FLAG_ENCRYPTED) != 0;
    file->is_compressed = (header->flags & FLAG_COMPRESSED) != 0;
    file->corrupted = 0;
    progress_init(&file->progress, header->total_size, header->total_section_count,
        header->filename);
    return 0;
}

/* Takes ownership of data, which must contain header->section_size bytes. */
static int extracting_file_process_block(ExtractingFile* file, const BlockHeader* header,
    uint8_t* data, uint32_t stored_crc) {
    uint32_t original_len = header->original_size;
    uint32_t data_len = header->section_size;

    if (header->section_id != file->expected_section_id) {
        printf("Warning: File '%s' section id mismatch: expected %llu, found %llu\n",
            file->filename, (unsigned long long)file->expected_section_id,
            (unsigned long long)header->section_id);
        file->corrupted = 1;
    }
    if (header->data_offset != file->current_size) {
        printf("Warning: File '%s' data offset mismatch: expected %llu, found %llu\n",
            file->filename, (unsigned long long)file->current_size,
            (unsigned long long)header->data_offset);
        file->corrupted = 1;
        if (header->data_offset < header->total_size &&
            _fseeki64(file->outfile, header->data_offset, SEEK_SET) == 0) {
            file->current_size = header->data_offset;
        }
    }

    if (data_len == 0) {
        free(data);
        if (stored_crc != 0) {
            printf("Warning: Empty file %s has non-zero CRC 0x%08x\n", file->filename, stored_crc);
            file->corrupted = 1;
        }
        return 0;
    }

    uint32_t crc = crc32_calc(data, data_len);
    if (header->flags & FLAG_ENCRYPTED) {
        if (!g_encryption_enabled) {
            printf("Error: The file is encrypted, but no password provided\n");
            file->corrupted = 1;
        }
        else if (data_len % AES_BLOCK_SIZE != 0) {
            printf("Error: Invalid encrypted section size for %s\n", file->filename);
            file->corrupted = 1;
        }
        else {
            process_data_block(data, data_len, header->header_crc32, 0);
            uint32_t unpadded_len;
            if (pkcs7_unpad(data, data_len, &unpadded_len) < 0) {
                printf("Error: PKCS#7 unpad failed\n");
                file->corrupted = 1;
            }
            else {
                data_len = unpadded_len;
            }
        }
    }

    uint8_t* final_data = data;
    uint32_t final_len = data_len;
    if (header->flags & FLAG_COMPRESSED) {
        int has_dict = (header->flags & FLAG_DICT_COMPRESSED) != 0;
        uint8_t* decompressed = decompress_zstd_with_dict(data, data_len, original_len, has_dict);
        if (!decompressed) {
            printf("Error: Decompression failed for %s section id %llu\n", file->filename,
                (unsigned long long)header->section_id);
            file->corrupted = 1;
        }
        else {
            free(data);
            final_data = decompressed;
            final_len = original_len;
        }
    }

    size_t write_len = final_len > original_len ? original_len : final_len;
    if (fwrite(final_data, 1, write_len, file->outfile) != write_len) {
        printf("Error: Failed to write data for %s section id %llu\n", file->filename,
            (unsigned long long)header->section_id);
        free(final_data);
        return -1;
    }
    if (write_len < original_len &&
        _fseeki64(file->outfile, original_len - write_len, SEEK_CUR) != 0) {
        printf("Error: Failed to seek output file %s\n", file->filename);
        free(final_data);
        return -1;
    }
    free(final_data);

    if (crc != stored_crc) {
        printf("Error: File %s section id %llu CRC check failed\n", file->filename,
            (unsigned long long)header->section_id);
        printf("       Calculated: 0x%08x, Stored: 0x%08x\n", crc, stored_crc);
        file->corrupted = 1;
    }
    file->current_size += original_len;
    file->expected_section_id = header->section_id + 1;
    progress_update(&file->progress, file->current_size, header->section_id, 0);
    return 0;
}

static int extracting_file_complete(ExtractingFile* file, int* extracted_count,
    int* corrupted_files) {
    progress_finish(&file->progress);
    fclose(file->outfile);
    file->outfile = NULL;

    if (file->corrupted) {
        char original_path[PATH_LEN_FOR_PROC];
        char corrupted_path[PATH_LEN_FOR_PROC];
        build_output_path(g_output_path, file->filename, original_path, sizeof(original_path));
        snprintf(corrupted_path, sizeof(corrupted_path), "%s.corrupted", original_path);
        printf("File %s corrupted, rename to %s\n", file->filename, corrupted_path);
        if (rename_utf8(original_path, corrupted_path) != 0) {
            printf("File %s rename to %s failed\n", file->filename, corrupted_path);
        }
        (*corrupted_files)++;
        return -1;
    }

    (*extracted_count)++;
    char flags_str[32] = "";
    if (file->is_encrypted && g_encryption_enabled) strcat(flags_str, "decrypted");
    if (file->is_compressed) {
        if (strlen(flags_str) > 0) strcat(flags_str, " ");
        strcat(flags_str, "decompressed");
    }
    if (strlen(flags_str) > 0) {
        printf("Successfully extracted: %s (%llu bytes) (%s)\n", file->filename,
            (unsigned long long)file->expected_size, flags_str);
    }
    else {
        printf("Successfully extracted: %s (%llu bytes)\n", file->filename,
            (unsigned long long)file->expected_size);
    }
    return 0;
}

int extract_archive(const char* archive_name, char** files, int file_count) {
    VolumeReadContext vol_ctx;
    int ret = 0;  // 统一返回值

    // 用于统计
    int extracted_count = 0;
    int corrupted_files = 0;
    int file_not_found = 0;
    int total_file_in_archive = 0;
    int total_dir_in_archive = 0;

    ExtractingFile* extracting_files = NULL;
    int extracting_count = 0;
    int extracting_capacity = 0;

    // 检查是否需要提取所有文件
    // 如果 file_count == 0，表示提取所有文件
    int extract_all = (file_count == 0);

    if (extract_all) {
        printf("Extracting all files\n");
    }
    else {
        printf("Files to extract:\n");
        for (int i = 0; i < file_count; i++) {
            printf("  %s\n", files[i]);
        }
    }

    if (g_output_path[0] != '\0') {
        printf("Output directory: %s\n", g_output_path);
        create_directories(g_output_path);
    }

    printf("Scanning archive and extracting files...\n");

    // 如果不是提取所有文件，初始化提取文件列表
    if (!extract_all) {
        extracting_capacity = file_count;
        extracting_files = (ExtractingFile*)calloc(extracting_capacity, sizeof(ExtractingFile));
        if (!extracting_files) {
            printf("Error: Out of memory\n");
            ret = -1;
            goto cleanup;
        }
        extracting_count = file_count;
        for (int i = 0; i < file_count; i++) {
            strncpy(extracting_files[i].filename, files[i], MAX_PATH_LEN - 1);
            extracting_files[i].filename[MAX_PATH_LEN - 1] = '\0';
            extracting_files[i].outfile = NULL;
            extracting_files[i].expected_size = 0;
            extracting_files[i].current_size = 0;
            extracting_files[i].expected_section_id = 0;
            extracting_files[i].total_sections = 0;
            extracting_files[i].is_encrypted = 0;
            extracting_files[i].is_compressed = 0;
            extracting_files[i].corrupted = 0;
            extracting_files[i].found = 0;
        }
    }

    // 开始扫描归档
    if (volume_read_init(&vol_ctx, archive_name) != 0) {
        ret = -1;
        goto cleanup;
    }
    g_vol_read_ctx = &vol_ctx;

    BlockHeader header;
    long long start_pos = 0;
    long long pos = 0;
    uint64_t block_num = 0;
    int result;
    char datetime_str[20];

    long long filesize = vol_ctx.file_size;

    while (1) {
        // 查找下一个块
        pos = find_next_magic(vol_ctx.file, start_pos, filesize);
        if (pos == -1) {
            // 尝试下一个分卷
            if (volume_read_next(&vol_ctx) != 0) {
                break;  // 没有更多分卷
            }
            start_pos = 0;
            filesize = vol_ctx.file_size;
            continue;
        }

        // 读取块头
        if (!read_block_header(&header,NULL)) {
            start_pos = pos + 1;
            continue;
        }

        // 验证块头
        result = validate_block_header(&header, pos, start_pos, &block_num);
        if (result < 0) {
            start_pos = pos + 1;
            continue;
        }

        if (header.flags & FLAG_RS_REDUNDANT) {
            archive_seek(header.section_size + CRC32_SIZE, SEEK_CUR);
            start_pos = archive_tell();
            continue;
        }

        // 格式化时间（用于显示）
        format_datetime(header.mtime, datetime_str, sizeof(datetime_str));

        // 处理目录
        if (header.magic == MAGIC_NUMBER_DIR) {
            total_dir_in_archive++;
            // 读取CRC并跳过
            uint32_t stored_crc;
            read_crc32(&stored_crc,NULL);

            // 如果需要提取所有文件，创建目录
            if (extract_all) {
                char dir_path[MAX_PATH_LEN];
                strcpy(dir_path, header.filename);
                // 移除末尾的'/'
                size_t len = strlen(dir_path);
                if (len > 0 && dir_path[len - 1] == '/') {
                    dir_path[len - 1] = '\0';
                }

                printf("Creating directory: %s\n", dir_path);
                create_directories_with_root(g_output_path, dir_path);
            }

            start_pos = archive_tell();
            continue;
        }

        // 处理文件
        if (header.magic == MAGIC_NUMBER_FILE) {
            int should_extract = extract_all;
            int file_index = -1;

            if (!extract_all) {
                // 检查是否需要提取这个文件
                for (int i = 0; i < extracting_count; i++) {
                    // 精确匹配
                    if (strcmp(header.filename, extracting_files[i].filename) == 0) {
                        should_extract = 1;
                        file_index = i;
                        extracting_files[i].found = 1;
                        break;
                    }
                }
            }
            else {
                // 提取所有文件，需要动态分配 extracting_files
                // 检查是否已有这个文件的记录
                for (int i = 0; i < extracting_count; i++) {
                    if (strcmp(extracting_files[i].filename, header.filename) == 0) {
                        file_index = i;
                        should_extract = 1;
                        break;
                    }
                }

                // 如果是新文件，添加到列表
                if (file_index == -1) {
                    if (extracting_count >= extracting_capacity) {
                        extracting_capacity = extracting_capacity ? extracting_capacity * 2 : 16;
                        ExtractingFile* new_files = (ExtractingFile*)realloc(extracting_files,
                            extracting_capacity * sizeof(ExtractingFile));
                        if (!new_files) {
                            printf("Error: Out of memory while adding new file, aborting extraction\n");
                            ret = -1;
                            goto cleanup;
                        }
                        extracting_files = new_files;
                        memset(&extracting_files[extracting_count], 0,
                            (extracting_capacity - extracting_count) * sizeof(ExtractingFile));
                    }

                    file_index = extracting_count;
                    extracting_count++;
                    strncpy(extracting_files[file_index].filename, header.filename, MAX_PATH_LEN - 1);
                    extracting_files[file_index].filename[MAX_PATH_LEN - 1] = '\0';
                    extracting_files[file_index].outfile = NULL;
                    extracting_files[file_index].expected_size = 0;
                    extracting_files[file_index].current_size = 0;
                    extracting_files[file_index].expected_section_id = 0;
                    extracting_files[file_index].total_sections = 0;
                    extracting_files[file_index].is_encrypted = 0;
                    extracting_files[file_index].is_compressed = 0;
                    extracting_files[file_index].corrupted = 0;
                    extracting_files[file_index].found = 1;

                    should_extract = 1;
                }
            }

            if (!should_extract) {
                // 不需要提取，跳过数据块和CRC
                if (header.section_size > 0) {
                    archive_seek(header.section_size + CRC32_SIZE, SEEK_CUR);
                }
                else {
                    archive_seek(CRC32_SIZE, SEEK_CUR);
                }
                start_pos = archive_tell();
                continue;
            }

            // 需要提取这个文件
            if (file_index >= 0 && extracting_files[file_index].outfile == NULL) {
                total_file_in_archive++;
                if (extracting_file_open(&extracting_files[file_index], &header) != 0) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (file_index >= 0 && extracting_files[file_index].outfile) {
                ExtractingFile* ef = &extracting_files[file_index];
                uint8_t* data_buffer = NULL;
                uint32_t stored_crc;
                if (header.section_size > 0) {
                    data_buffer = (uint8_t*)malloc(header.section_size);
                    if (!data_buffer) {
                        printf("Error: Out of memory allocating %u bytes\n", header.section_size);
                        ret = -1;
                        goto cleanup;
                    }
                    size_t actual_read = archive_read(data_buffer, header.section_size);
                    if (actual_read != header.section_size) {
                        printf("Error: Failed to read data for %s, expected %u bytes, got %zu\n",
                            ef->filename, header.section_size, actual_read);
                        ef->corrupted = 1;
                        memset(data_buffer + actual_read, 0, header.section_size - actual_read);
                    }
                }
                read_crc32(&stored_crc, NULL);
                if (extracting_file_process_block(ef, &header, data_buffer, stored_crc) != 0) {
                    ret = -1;
                    goto cleanup;
                }
                if (ef->current_size >= ef->expected_size) {
                    if (extracting_file_complete(ef, &extracted_count, &corrupted_files) != 0) {
                        ret = -1;
                    }
                }
            }

            start_pos = archive_tell();
        }
    }

cleanup:
    // 关闭所有可能还打开的文件，还打开说明没读取完整（文件损坏）
    if (extracting_files) {
        for (int i = 0; i < extracting_count; i++) {
            ExtractingFile* ef = &extracting_files[i];
            if (ef->outfile) {
                fclose(ef->outfile);
                ef->outfile = NULL;
                char new_file_name[PATH_LEN_FOR_PROC];
                char original_path[PATH_LEN_FOR_PROC];
                build_output_path(g_output_path, ef->filename, original_path, sizeof(original_path));
                snprintf(new_file_name, sizeof(new_file_name), "%s.corrupted", original_path);

                printf("\nFile %s was incomplete (expected %llu bytes, got %llu), rename to %s\n",
                    extracting_files[i].filename,
                    extracting_files[i].expected_size,
                    extracting_files[i].current_size, new_file_name
                );
                if (rename_utf8(original_path, new_file_name) != 0) {
                    printf("File %s rename to %s failed\n", ef->filename, new_file_name);
                }
                corrupted_files++;
            }

            if (!extract_all && !extracting_files[i].found) {
                printf("Warning: File '%s' not found in archive\n", extracting_files[i].filename);
                file_not_found++;
            }
        }

        free(extracting_files);
    }

    // 清理卷读取上下文
    if (g_vol_read_ctx) {
        volume_read_close(&vol_ctx);
        g_vol_read_ctx = NULL;
    }

    // 输出总结
    printf("\nExtraction summary:\n");
    if (!extract_all) {
        printf("  - Requested files: %d\n", file_count);
        printf("  - Found and extracted: %d\n", extracted_count);
        printf("  - Not found: %d\n", file_not_found);
    }
    else {
        printf("  - Total file in archive: %d\n", total_file_in_archive);
        printf("  - Total directory in archive: %d\n", total_dir_in_archive);
        printf("  - Successfully extracted: %d\n", extracted_count);
    }
    printf("  - Corrupted files: %d\n", corrupted_files);

    if (corrupted_files > 0 || file_not_found > 0) {
        if (ret == 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        printf("Extraction completed successfully\n");
    }

    return ret;
}
int rs_group_reassemble_and_write(DataGroupContext* group_ctx, int parity_shards_count, uint64_t group_index, uint32_t split_count) {
    if (!group_ctx || group_ctx->front == NULL) return -1;

    uint32_t effective_split_count = split_count;
    int effective_parity_shards_count = parity_shards_count;

    if (g_rs_fixed_size_enabled) {
        uint64_t total_size = group_ctx->total_size;
        int best_data_shards = 0;
        int best_parity_shards = 0;
        int best_total_shards = 0;

        /* Search for the largest valid total shard count. For each candidate
         * data-shard count, the parity count is the minimum needed to reach
         * the requested redundancy size. */
        for (int data_count = 1; data_count < 256; data_count++) {
            uint64_t shard_size = (total_size + (uint64_t)data_count - 1) /
                (uint64_t)data_count;
            if (shard_size == 0 || shard_size > UINT32_MAX) {
                continue;
            }

            uint64_t parity_needed = g_rs_fixed_size / shard_size;
            if (g_rs_fixed_size % shard_size != 0) {
                parity_needed++;
            }
            if (parity_needed == 0) {
                parity_needed = 1;
            }
            if (parity_needed > (uint64_t)(256 - data_count)) {
                continue;
            }

            int total_shards = data_count + (int)parity_needed;
            if (total_shards > best_total_shards ||
                (total_shards == best_total_shards &&
                    (int)parity_needed > best_parity_shards)) {
                best_data_shards = data_count;
                best_parity_shards = (int)parity_needed;
                best_total_shards = total_shards;
            }
        }

        if (best_data_shards == 0) {
            /* The requested redundancy is larger than this tiny group can
             * represent with at most 256 shards. Use one data shard and as
             * many parity shards as possible. */
            uint64_t shard_size = total_size;
            uint64_t parity_needed = (shard_size > 0) ?
                (g_rs_fixed_size / shard_size + (g_rs_fixed_size % shard_size != 0)) : 1;
            if (parity_needed > 255) {
                parity_needed = 255;
            }
            if (parity_needed == 0) {
                parity_needed = 1;
            }
            best_data_shards = 1;
            best_parity_shards = (int)parity_needed;
            best_total_shards = best_data_shards + best_parity_shards;
            printf("Warning: RS redundancy target %llu bytes cannot be reached for "
                "group size %llu with 256 shards; using %d data and %d parity shards\n",
                (unsigned long long)g_rs_fixed_size,
                (unsigned long long)total_size,
                best_data_shards, best_parity_shards);
        }

        effective_split_count = (uint32_t)best_data_shards;
        effective_parity_shards_count = best_parity_shards;
        printf("RS group %llu: %d data shards, %d parity shards, %d total shards "
            "(target redundancy %llu bytes)\n",
            (unsigned long long)group_index,
            best_data_shards, best_parity_shards, best_total_shards,
            (unsigned long long)g_rs_fixed_size);
    }

    ReassembledContext* split_info = reassemble_data_by_count(group_ctx, effective_split_count);
    if (!split_info) return -1;

    uint32_t max_block_size = (uint32_t)split_info->split_size;
    ReassembledBlock* current = split_info->block_info;
    int data_shards_count = split_info->block_count;
    int total_shards_count = data_shards_count + effective_parity_shards_count;

    // 初始化指针
    fec_t* code = NULL;
    uint8_t** data_shards = NULL;
    uint8_t** parity_shards = NULL;
    uint32_t* blocknums = NULL;
    uint8_t* rs_data = NULL;
    int ret = -1;

    // 为RS编码准备数据
    data_shards = (uint8_t**)calloc(data_shards_count, sizeof(uint8_t*));
    parity_shards = (uint8_t**)calloc(effective_parity_shards_count, sizeof(uint8_t*));

    if (!data_shards || !parity_shards) {
        goto cleanup;
    }

    current = split_info->block_info;
    int i = 0;
    while (current != NULL) {
        data_shards[i] = &split_info->data[current->original_offset];
        current = current->next;
        i++;
    }

    // 初始化校验分片
    for (int i = 0; i < effective_parity_shards_count; i++) {
        parity_shards[i] = (uint8_t*)calloc(max_block_size, 1);
        if (!parity_shards[i]) {
            goto cleanup;
        }
    }

    if (data_shards_count <= 0 || effective_parity_shards_count <= 0 ||
        total_shards_count > 256) {
        printf("Error: RS total shard count must be between 1 and 256\n");
        goto cleanup;
    }

    code = fec_new((unsigned short)data_shards_count, (unsigned short)total_shards_count);
    if (!code) {
        printf("Error: Failed to create GF(2^8) RS encoder\n");
        goto cleanup;
    }

    blocknums = malloc(sizeof(uint32_t) * effective_parity_shards_count);

    if (!blocknums) {
        ret = -1;
        goto cleanup;
    }

    for (int i = 0; i < effective_parity_shards_count; i++) {
        blocknums[i] = (uint32_t)(i + data_shards_count);
    }

    // 执行编码
    fec_encode(code, (const gf* const*)data_shards, (gf* const*)parity_shards,
        (const unsigned int*)blocknums, effective_parity_shards_count, max_block_size);

    // 计算并写入RS冗余块
    uint64_t total_section_count = effective_parity_shards_count;

    for (int i = 0; i < effective_parity_shards_count; i++) {
        // 准备RS块头
        BlockHeader header = { 0 };
        header.magic = MAGIC_NUMBER_FILE;
        snprintf(header.filename, MAX_PATH_LEN, "RS_REDUNDANT_GROUP_%llu",
            (unsigned long long)group_index);
        header.mtime = time(NULL);
        header.section_id = i;
        header.total_section_count = total_section_count;
        header.flags = FLAG_RS_REDUNDANT;

        // 准备RS块数据头
        RSBlockHeader rs_header;
        RSBlockHeader rs_header_be;
        rs_header.chunk_count = split_info->block_count;
        rs_header.chunk_info_size = sizeof(RSDataChunkInfo);
        rs_header.data_size = max_block_size;

        // 计算总数据大小
        uint32_t total_data_size = sizeof(RSBlockHeader) +
            data_shards_count * sizeof(RSDataChunkInfo) +
            max_block_size;

        rs_data = (uint8_t*)malloc(total_data_size);
        if (!rs_data) {
            ret = -1;
            goto cleanup;
        }

        uint8_t* ptr = rs_data;

        // 写入RS块头
        rs_block_header_host_to_be(&rs_header, &rs_header_be);
        memcpy(ptr, &rs_header_be, sizeof(RSBlockHeader));
        ptr += sizeof(RSBlockHeader);

        // 写入数据分块信息
        current = split_info->block_info;
        while (current != NULL) {
            RSDataChunkInfo info;
            RSDataChunkInfo info_be;
            info.block_index = current->block_index;
            info.offset = current->block_offset;
            info.size = current->size;
            info.crc32 = current->crc32;
            rs_data_chunk_info_host_to_be(&info, &info_be);
            memcpy(ptr, &info_be, sizeof(RSDataChunkInfo));
            ptr += sizeof(RSDataChunkInfo);
            current = current->next;
        }

        // 写入冗余数据
        memcpy(ptr, parity_shards[i], max_block_size);

        header.section_size = total_data_size;
        header.original_size = total_data_size;
        header.total_size = total_data_size * total_section_count;

        // 写入块头
        if (write_block_header(&header, 1) != sizeof(BlockHeader)) {
            ret = -1;
            goto cleanup;
        }

        // 写入数据
        if (archive_write(rs_data, total_data_size, 0, 1) != total_data_size) {
            ret = -1;
            goto cleanup;
        }

        // 写入CRC
        CRC32_Context crc_ctx;
        crc32_init(&crc_ctx);
        crc32_update(&crc_ctx, rs_data, total_data_size);
        uint32_t crc = crc32_final(&crc_ctx);

        free(rs_data);
        rs_data = NULL;

        if (write_crc32(crc, 1) != sizeof(uint32_t)) {
            ret = -1;
            goto cleanup;
        }
    }

    ret = 0;  // 成功

cleanup:
    // 统一释放所有资源
    if (code) {
        fec_free(code);
    }
    if (blocknums) {
        free(blocknums);
    }

    if (rs_data) {
        free(rs_data);
    }

    if (data_shards) {
        free(data_shards);
    }

    if (parity_shards) {
        for (int i = 0; i < effective_parity_shards_count; i++) {
            if (parity_shards[i]) {
                free(parity_shards[i]);
            }
        }
        free(parity_shards);
    }

    free_reassembled_info(split_info);

    return ret;
}

// 解析RS块信息（从内存中解析）
int parse_rs_block_info(uint8_t* rs_data, size_t rs_size, RSDataChunkInfo** chunks,
    int* chunk_count, uint32_t* shard_size) {
    size_t metadata_size;
    if (rs_size < sizeof(RSBlockHeader)) {
        return -1;
    }

    RSBlockHeader header;
    RSBlockHeader header_be;
    memcpy(&header_be, rs_data, sizeof(RSBlockHeader));
    rs_block_header_be_to_host(&header_be, &header);

    if (header.chunk_info_size != sizeof(RSDataChunkInfo)) {
        return -1;
    }
    if (header.chunk_count == 0 || header.chunk_count > INT_MAX ||
        header.chunk_count > (SIZE_MAX - sizeof(RSBlockHeader)) / sizeof(RSDataChunkInfo)) {
        return -1;
    }
    metadata_size = sizeof(RSBlockHeader) + (size_t)header.chunk_count * sizeof(RSDataChunkInfo);
    if (metadata_size > rs_size || header.data_size > rs_size - metadata_size) {
        return -1;
    }

    *chunk_count = header.chunk_count;
    *shard_size = header.data_size;
    *chunks = (RSDataChunkInfo*)malloc(header.chunk_count * sizeof(RSDataChunkInfo));
    if (!*chunks) {
        return -1;
    }

    uint8_t* ptr = rs_data + sizeof(RSBlockHeader);
    for (uint32_t i = 0; i < header.chunk_count; i++) {
        RSDataChunkInfo info_be;
        memcpy(&info_be, ptr, sizeof(RSDataChunkInfo));
        rs_data_chunk_info_be_to_host(&info_be, &(*chunks)[i]);
        ptr += sizeof(RSDataChunkInfo);
    }

    return 0;
}

// 从DataGroupContext中提取数据分片和校验分片
typedef struct {
    uint8_t** shards;      // 数据分片数组
    uint8_t* marks;      // 数据分片是否损坏
    int data_shards_count;      // 数据分片数量
    int parity_shards_count;    // 校验分片数量
    uint32_t shard_size;        // 每个分片的大小
    uint8_t* data_storage;      // contiguous storage for all data shards
    RSDataChunkInfo* chunks;    // 分片信息
    int chunk_count;            // 分片信息数量
    int available_shards_count;
    int reconstruction_impossible;
} RSShardsInfo;

// 释放RSShardsInfo
void free_rs_shards_info(RSShardsInfo* rs_info) {
    int nr_shards = rs_info->data_shards_count + rs_info->parity_shards_count;
    if (rs_info->shards) {
        for (int i = 0; i < nr_shards; i++) {
            if (rs_info->shards[i] &&
                (!rs_info->data_storage || i >= rs_info->data_shards_count)) {
                free(rs_info->shards[i]);
            }
        }
        free(rs_info->shards);
    }

    free(rs_info->data_storage);

    if (rs_info->marks) {
        free(rs_info->marks);
    }

    if (rs_info->chunks) {
        free(rs_info->chunks);
    }

    memset(rs_info, 0, sizeof(RSShardsInfo));
}


// 从DataGroupContext提取RS分片信息
int extract_rs_shards_from_group(DataGroupContext* group_ctx, RSShardsInfo* rs_info) {
    if (!group_ctx || !rs_info) {
        return -1;
    }

    memset(rs_info, 0, sizeof(RSShardsInfo));

    // 第一步：扫描所有块，找出RS冗余块
    DataBlock* current = group_ctx->front;
    RepairBlockInfo* rs_blocks = NULL;
    int rs_block_count = 0;
    int rs_block_capacity = 0;
    RepairBlockInfo* data_blocks = NULL;
    int data_block_count = 0;
    int data_block_capacity = 0;
    BlockHeader header;
    int nr_shards = 0;
    uint8_t** shards = NULL;
    uint8_t* marks = NULL;
    RSDataChunkInfo* chunks = NULL;

    while (current != NULL) {
        // 解析块头（块数据的开头是BlockHeader）
        if (current->size >= sizeof(BlockHeader)) {
            header_be_to_host((BlockHeader*)current->data, &header);

            // 检查是否是RS冗余块
            if (header.flags & FLAG_RS_REDUNDANT) {
                if (header.flags & FLAG_RS_EXTENDED_FIELD) {
                    printf("Unsupported RS encoding format in this archive\n");
                    goto cleanup;
                }
                // 扩展RS块数组
                if (rs_block_count >= rs_block_capacity) {
                    rs_block_capacity = rs_block_capacity ? rs_block_capacity * 2 : 4;
                    RepairBlockInfo *tmp = (RepairBlockInfo*)realloc(rs_blocks,
                        rs_block_capacity * sizeof(RepairBlockInfo));
                    if (!tmp) {
                        goto cleanup;
                    }
                    rs_blocks = tmp;
                }

                // 记录RS块信息
                rs_blocks[rs_block_count].block_id = header.block_id;
                rs_blocks[rs_block_count].block_size = current->size;
                rs_blocks[rs_block_count].section_id = header.section_id;
                rs_blocks[rs_block_count].section_size = header.section_size;
                rs_blocks[rs_block_count].owner = current;
                rs_blocks[rs_block_count].total_sections = header.total_section_count;
                rs_blocks[rs_block_count].data = current->data;
                rs_blocks[rs_block_count].payload_data = current->data + sizeof(BlockHeader);
                rs_block_count++;
            }
            else {
                // 普通数据块
                if (data_block_count >= data_block_capacity) {
                    data_block_capacity = data_block_capacity ? data_block_capacity * 2 : 16;
                    RepairBlockInfo* tmp = (RepairBlockInfo*)realloc(data_blocks,
                        data_block_capacity * sizeof(RepairBlockInfo));
                    if (!tmp) {
                        goto cleanup;
                    }
                    data_blocks = tmp;
                }

                // 记录数据块信息
                data_blocks[data_block_count].block_id = header.block_id;
                data_blocks[data_block_count].section_id = header.section_id;
                data_blocks[data_block_count].total_sections = header.total_section_count;
                data_blocks[data_block_count].block_size = current->size;
                data_blocks[data_block_count].section_size = header.section_size;
                data_blocks[data_block_count].owner = current;
                data_blocks[data_block_count].data = current->data;
                data_blocks[data_block_count].payload_data = current->data + sizeof(BlockHeader);
                data_block_count++;
            }
        }
        current = current->next;
    }

    if (rs_block_count == 0) {
        printf("No RS redundancy blocks found in this group\n");
        goto cleanup;
    }

    // 第二步：从第一个RS块解析分片信息
    int chunk_count = 0;
    uint32_t shard_size = 0;

    if (parse_rs_block_info(rs_blocks[0].payload_data, rs_blocks[0].section_size,
        &chunks, &chunk_count, &shard_size) != 0) {
        printf("Failed to parse RS block info\n");
        goto cleanup;
    }

    // 第三步：准备分片数组
    int data_shards_count = chunk_count;
    uint64_t parity_shards_count = rs_blocks[0].total_sections;

    if (data_shards_count <= 0 || parity_shards_count == 0 ||
        data_shards_count > 256 || parity_shards_count > 256 - (uint64_t)data_shards_count) {
        printf("Invalid RS shard metadata\n");
        goto cleanup;
    }
    nr_shards = data_shards_count + (int)parity_shards_count;

    shards = (uint8_t**)calloc(nr_shards, sizeof(uint8_t*));
    marks = (uint8_t*)calloc(nr_shards, sizeof(uint8_t));

    if (!shards || !marks) {
        printf("Out of memory for shard arrays\n");
        goto cleanup;
    }

    for (int i = 0; i < nr_shards; i++) {
        marks[i] = 1;
    }

    /* Rebuild each data shard from the block identified by its RS metadata.
     * If bytes were deleted from the archive, a whole block may be absent;
     * packing the remaining blocks sequentially would shift every later shard. */
    if ((size_t)data_shards_count > SIZE_MAX / shard_size) {
        printf("Out of memory for data shards\n");
        goto cleanup;
    }
    /* RS encodes the unused tail of a short final shard as zeroes. */
    rs_info->data_storage = (uint8_t*)calloc((size_t)data_shards_count, shard_size);
    if (!rs_info->data_storage) {
        printf("Out of memory for data shards\n");
        goto cleanup;
    }
    for (int i = 0; i < data_shards_count; i++) {
        shards[i] = rs_info->data_storage + (size_t)i * shard_size;
    }

    /* Allocate every parity shard before releasing any source block. If this
     * fails, the fallback path can still write the untouched group data. */
    for (int i = 0; i < rs_block_count; i++) {
        if (rs_blocks[i].section_id >= parity_shards_count) {
            continue;
        }
        int shard_index = (int)rs_blocks[i].section_id + data_shards_count;
        if (!shards[shard_index]) {
            shards[shard_index] = (uint8_t*)calloc(shard_size, 1);
            if (!shards[shard_index]) {
                printf("Out of memory for parity shard %llu\n", rs_blocks[i].section_id);
                goto cleanup;
            }
        }
    }

    for (int i = 0; i < chunk_count; i++) {
        RSDataChunkInfo* chunk = &chunks[i];
        int start_block = -1;
        for (int j = 0; j < data_block_count; j++) {
            if (data_blocks[j].block_id == chunk->block_index) {
                start_block = j;
                break;
            }
        }

        if (start_block >= 0) {
            uint32_t remaining = chunk->size;
            uint32_t source_offset = chunk->offset;
            uint32_t shard_offset = 0;
            for (int j = start_block; remaining > 0 && j < data_block_count; j++) {
                RepairBlockInfo* block = &data_blocks[j];
                if (source_offset > block->block_size) {
                    break;
                }
                uint32_t available = block->block_size - source_offset;
                uint32_t copy_size = remaining < available ? remaining : available;
                if (copy_size == 0) {
                    break;
                }
                memcpy(shards[i] + shard_offset, block->data + source_offset, copy_size);
                remaining -= copy_size;
                shard_offset += copy_size;
                source_offset = 0;
            }
            if (remaining == 0 && crc32_calc(shards[i], chunk->size) == chunk->crc32) {
                marks[i] = 0;
            }
        }
    }

    // 从RS块中填充校验分片
    for (int i = 0; i < rs_block_count; i++) {
        RepairBlockInfo* rs_block = &rs_blocks[i];
        if (rs_block->section_id >= parity_shards_count) {
            printf("  Warning: invalid RS section_id %llu\n", rs_block->section_id);
            continue;
        }
        // 提取校验数据（跳过RS块头和数据分片信息）
        uint8_t* rs_data_start = rs_block->payload_data + sizeof(RSBlockHeader) +
            chunk_count * sizeof(RSDataChunkInfo);
        uint32_t rs_data_size = rs_block->section_size - (sizeof(RSBlockHeader) +
            chunk_count * sizeof(RSDataChunkInfo));

        int shard_index = (int)rs_block->section_id + data_shards_count;
        if (rs_data_size >= shard_size) {
            memcpy(shards[shard_index], rs_data_start, shard_size);
            marks[shard_index] = 0;
        }
        else {
            printf("  Warning: RS block %llu has insufficient data\n", rs_block->block_id);
        }
        free(rs_block->owner->data);
        rs_block->owner->data = NULL;
    }

    int available_shards_count = 0;
    for (int i = 0; i < nr_shards; i++) {
        if (!marks[i]) {
            available_shards_count++;
        }
    }
    int reconstruction_impossible = available_shards_count < data_shards_count;

    /* Keep complete source blocks only when the available shard count proves
     * reconstruction is impossible. Otherwise the contiguous shard storage
     * owns the data and the original block buffers can be released. */
    if (!reconstruction_impossible) {
        for (int i = 0; i < data_block_count; i++) {
            free(data_blocks[i].owner->data);
            data_blocks[i].owner->data = NULL;
        }
    }

    // 填充输出结构
    rs_info->shards = shards;
    rs_info->marks = marks;
    rs_info->data_shards_count = data_shards_count;
    rs_info->parity_shards_count = (int)parity_shards_count;
    rs_info->shard_size = shard_size;
    /* data_storage owns all data shard pointers; parity shards are owned
     * individually by the shard array. */
    rs_info->chunks = chunks;
    rs_info->chunk_count = chunk_count;
    rs_info->available_shards_count = available_shards_count;
    rs_info->reconstruction_impossible = reconstruction_impossible;

    // 释放临时数组（不释放分片数据）
    free(data_blocks);
    free(rs_blocks);
    return 0;

cleanup:
    if (shards) {
        // 清理已分配的分片
        for (int i = 0; i < nr_shards; i++) {
            if (shards[i] && (!rs_info->data_storage || i >= data_shards_count)) {
                free(shards[i]);
            }
        }
        free(shards);
    }
    free(rs_info->data_storage);
    if (marks) 
        free(marks);
    if(chunks)
        free(chunks);
    if(data_blocks)
        free(data_blocks);
    if(rs_blocks)
        free(rs_blocks);
    return -1;
}

int fec_reconstruct(fec_t* code,
    unsigned char** shards,
    unsigned char* marks,
    uint32_t block_size)
{
    int i;
    int k, n;
    int pn = 0, j = 0;
    unsigned* indexes = NULL;
    unsigned char** inpkts = NULL;
    unsigned char** outpkts = NULL;
    int ret = 0;
    if (!code || !shards || !marks || block_size == 0) {
        return -1;
    }

    k = code->k;
    n = code->n;


    indexes = (unsigned*)malloc((size_t)k * sizeof(unsigned));
    inpkts = (unsigned char**)malloc((size_t)k * sizeof(unsigned char*));
    outpkts = (unsigned char**)malloc((size_t)(n - k) * sizeof(unsigned char*));
    if (!indexes || !inpkts || !outpkts) {
        ret = -1;
        goto end;
    }

    // 收集已有块和缺失块
    for (i = 0; i < k; i++) {
        if (!marks[i]) {
            inpkts[i] = shards[i];
            indexes[i] = (unsigned int)i;
        }
        else {
            int found = 0;
            while(pn < n - k) {
                if (!marks[k + pn]) {
                    inpkts[i] = shards[k + pn];
                    indexes[i] = (unsigned int)(k + pn);
                    outpkts[j++] = shards[i];
                    pn++;
                    found = 1;
                    break;
                }
                else {
                    pn++;
                }
            }
            if (!found) {
                // 可用块不足
                ret = -1;
                goto end;
            }
        }
    }


    fec_decode(code,
        (const gf* const*)inpkts,
        (gf* const*)outpkts,
        indexes,
        (size_t)block_size);

end:
    free(indexes);
    free(inpkts);
    free(outpkts);

    return ret;
}

typedef int (*RecoveredDataSink)(const uint8_t* data, size_t size, void* context);

int recovered_archive_write_sink(const uint8_t* data, size_t size, void* context) {
    (void)context;
    return archive_write(data, size, 0, 0) == size ? 0 : -1;
}

int write_original_group_data(DataGroupContext* group_ctx,
    RecoveredDataSink sink, void* sink_context) {
    int ret = 0;
    DataBlock* current = group_ctx->front;
    while (current != NULL) {
        if (current->data && current->size >= sizeof(BlockHeader) + CRC32_SIZE) {
            BlockHeader header;
            header_be_to_host((BlockHeader*)current->data, &header);
            if (!(header.flags & FLAG_RS_REDUNDANT) &&
                sink(current->data, current->size, sink_context) != 0) {
                printf("  Warning: Failed to write block id %llu (size=%u)\n",
                    (unsigned long long)current->block_index, current->size);
                ret = -1;
            }
        }
        current = current->next;
    }
    return ret;
}

// 恢复group
int recover_group_with_rs(DataGroupContext* group_ctx,
    RecoveredDataSink sink, void* sink_context) {
    if (!group_ctx) {
        return -1;
    }
    if (!sink) {
        return -1;
    }
    RSShardsInfo rs_info;
    int ret = 0;
    if (extract_rs_shards_from_group(group_ctx, &rs_info) != 0) {
        printf("Error: Failed to prepare RS shards; writing original group data without repair\n");
        write_original_group_data(group_ctx, sink, sink_context);
        return -1;
    }

    if (rs_info.reconstruction_impossible) {
        printf("RS reconstruction impossible: %d available shards, %d required\n",
            rs_info.available_shards_count, rs_info.data_shards_count);
        printf("Writing original complete data blocks for best-effort output\n");
        if (write_original_group_data(group_ctx, sink, sink_context) != 0) {
            ret = -1;
        }
        free_rs_shards_info(&rs_info);
        return -1;
    }

    // 创建RS解码器
    int total_shards = rs_info.data_shards_count + rs_info.parity_shards_count;

    int is_corrupted = 0;

    for (int i = 0; i < total_shards; i++) {
        if (rs_info.marks[i] == 1) {
            printf("Shard index %d corrupted, data %d shards, parity %d shards\n",i, rs_info.data_shards_count, rs_info.parity_shards_count);
            is_corrupted = 1;
        }
    }

    if (is_corrupted) {
        int decode_result = -1;
        printf("Reconstructing missing chunks with GF(2^8)\n");
        if (total_shards <= 256) {
            fec_t* code = fec_new((unsigned short)rs_info.data_shards_count, (unsigned short)total_shards);
            if (code) {
                decode_result = fec_reconstruct(code, rs_info.shards, rs_info.marks, rs_info.shard_size);
                fec_free(code);
            }
        }

        if (decode_result == 0) {
            for (int i = 0; i < rs_info.data_shards_count; i++) {
                if (rs_info.marks[i] &&
                    crc32_calc(rs_info.shards[i], rs_info.chunks[i].size) != rs_info.chunks[i].crc32) {
                    printf("RS reconstruction produced an invalid data shard %d\n", i);
                    decode_result = -1;
                    break;
                }
            }
        }
        if (decode_result == 0) {
            printf("RS reconstruction successful!\n");
        }
        else {
            printf("RS reconstruction failed\n");
            ret = -1;
            printf("Writing unrepaired data shards for best-effort output\n");
        }
        
    }

    for (int i = 0; i < rs_info.data_shards_count; i++) {
        uint32_t size = rs_info.chunks[i].size;
        if (sink(rs_info.shards[i], size, sink_context) != 0) {
            printf("  Warning: Failed to write shards (size=%u)\n", size);
            ret = -1;
        }
    }
    free_rs_shards_info(&rs_info);

    return ret;
}


// 修复归档的主函数
int repair_archive(const char* archive_name, const char* repaired_archive_name) {
    fec_init();
    VolumeReadContext vol_read_ctx;
    VolumeContext vol_write_ctx;
    DataGroupContext* group_ctx = NULL;

    int ret = 0;
    printf("========================================\n");
    printf("LXAR Archive Repair\n");
    printf("========================================\n\n");

    // 初始化读取上下文
    if (volume_read_init(&vol_read_ctx, archive_name) != 0) {
        ret = -1;
        goto cleanup;
    }
    g_vol_read_ctx = &vol_read_ctx;

    // 用于存储所有需要修复的组
    group_ctx = init_data_group_context();
    if (group_ctx == NULL) {
        ret = -1;
        goto cleanup;
    }

    // 初始化写入
    if (volume_init(&vol_write_ctx, repaired_archive_name, 0) != 0) {
        ret = -1;
        goto cleanup;
    }
    g_vol_ctx = &vol_write_ctx;

    BlockHeader header,raw_header;
    long long start_pos = 0;
    long long pos = 0;
    uint64_t block_num = 0;
    int result;
    uint64_t last_group_id = (uint64_t)-1;

    long long filesize = vol_read_ctx.file_size;

    printf("Scanning archive and detecting corruption...\n\n");

    while (1) {
        // 查找下一个块
        pos = find_next_magic(vol_read_ctx.file, start_pos, filesize);
        if (pos == -1) {
            // 尝试下一个分卷
            if (volume_read_next(&vol_read_ctx) != 0) {
                break;
            }
            start_pos = 0;
            filesize = vol_read_ctx.file_size;
            continue;
        }

        // 保存块起点。若块长度或数据已损坏，当前游标可能已经越过后续块，
        // 需要从该起点后一字节重新搜索，而不是从错误的游标继续扫描。
        long long block_start_pos = pos;

        // 读取块头
        if (!read_block_header(&header,&raw_header)) {
            printf("Warning: Failed to read block header at position %lld\n", pos);
            start_pos = pos + 1;
            continue;
        }

        // 验证块头
        result = validate_block_header(&header, pos, start_pos, &block_num);

        int block_available = 1;

        // 检查magic number
        if (header.magic != MAGIC_NUMBER_FILE && header.magic != MAGIC_NUMBER_DIR) {
            printf("Warning: Invalid magic number 0x%08x at position %lld\n",
                header.magic, pos);
        }

        // 读取数据并验证CRC
        uint32_t stored_crc = 0;
        uint32_t stored_raw_crc = 0;
        uint8_t* data_buffer = NULL;
        uint32_t data_len = header.section_size;
        int need_resync = 0;

        if (header.magic == MAGIC_NUMBER_FILE && header.section_size > 0) {
            // 读取数据
            data_buffer = (uint8_t*)malloc(data_len);
            if (data_buffer) {
                size_t actual_read = archive_read(data_buffer, data_len);
                if (actual_read != data_len) {
                    printf("Warning: Short read for block %llu (expected %u, got %zu)\n",
                        (unsigned long long)header.block_id, data_len, actual_read);
                    block_available = 0;
                    need_resync = 1;
                }
                else {
                    // 计算CRC
                    CRC32_Context crc_ctx;
                    crc32_init(&crc_ctx);
                    crc32_update(&crc_ctx, data_buffer, data_len);
                    uint32_t calc_crc = crc32_final(&crc_ctx);

                    // 读取存储的CRC
                    if (!read_crc32(&stored_crc,&stored_raw_crc)) {
                        block_available = 0;
                        need_resync = 1;
                    }

                    if (calc_crc != stored_crc) {
                        printf("Warning: CRC mismatch for block %llu (group %llu): calc=0x%08x, stored=0x%08x\n",
                            (unsigned long long)header.block_id,
                            (unsigned long long)header.block_group_id,
                            calc_crc, stored_crc);
                        /* Keep the block: RS may still recover chunks whose
                         * individual CRCs remain valid. Rescan afterward in
                         * case a deleted range made the declared length skip
                         * over the next header. */
                        need_resync = 1;
                    }
                }
            }
            else {
                printf("Error: Out of memory reading block %llu; repair aborted\n",
                    (unsigned long long)header.block_id);
                ret = -1;
                goto cleanup;
            }
        }
        else if (header.magic == MAGIC_NUMBER_FILE && header.section_size == 0) {
            // 空文件，只读取CRC
            if (!read_crc32(&stored_crc, &stored_raw_crc)) {
                block_available = 0;
                need_resync = 1;
            }
            if (stored_crc != 0) {
                printf("Warning: Empty file %s has non-zero CRC 0x%08x\n",
                    header.filename, stored_crc);
            }
        }
        else if (header.magic == MAGIC_NUMBER_DIR) {
            // 目录块，只读取CRC
            if (!read_crc32(&stored_crc, &stored_raw_crc)) {
                block_available = 0;
                need_resync = 1;
            }
            if (stored_crc != 0) {
                printf("Warning: Directory %s has non-zero CRC 0x%08x\n",
                    header.filename, stored_crc);
            }
        }

        if (need_resync && !block_available) {
            if (data_buffer) {
                free(data_buffer);
                data_buffer = NULL;
            }
            // header 已验证，从 payload 起点重新搜索后续 header。
            start_pos = block_start_pos + (long long)sizeof(BlockHeader);
            printf("Resyncing after corrupted block %llu (group %llu) from position 0x%llx\n",
                (unsigned long long)header.block_id,
                (unsigned long long)header.block_group_id,
                (unsigned long long)start_pos);
            continue;
        }

        if (block_available) {
            // group_id大于0的组才会有冗余数据
            if (header.block_group_id == 0) {
                size_t written = archive_write(&raw_header, sizeof(BlockHeader), 1, 0);;
                if (written != sizeof(BlockHeader)) {
                    printf("  Warning: Failed to write block id %llu header\n", header.block_id);
                }
                if (data_buffer) {
                    written = archive_write(data_buffer, header.section_size,0,0);
                    if (written != header.section_size) {
                        printf("  Warning: Failed to write block id %llu data\n", header.block_id);
                    }
                }
                written = archive_write(&stored_raw_crc, sizeof(uint32_t), 0, 0);
                if (written != sizeof(uint32_t)) {
                    printf("  Warning: Failed to write block id %llu crc32\n", header.block_id);
                }
            }
            else {

                if (last_group_id == (uint64_t)-1) {
                    last_group_id = header.block_group_id;
                }

                if (header.block_group_id != last_group_id) {
                    //print_data_group_context(group_ctx);
                    printf("Processing group index %llu\n", last_group_id);
                    if (recover_group_with_rs(group_ctx, recovered_archive_write_sink, NULL) < 0) {
                        ret = -1;
                    }
                    reset_data_group_context(group_ctx);
                }
                if (init_data_block(group_ctx, header.block_id, header.section_size + sizeof(BlockHeader) + CRC32_SIZE) >= 0) {
                    int buffer_result = write_to_data_block(group_ctx, group_ctx->current_block_index,
                        (uint8_t*)&raw_header, sizeof(BlockHeader));
                    if (data_buffer) {
                        buffer_result |= write_to_data_block(group_ctx, group_ctx->current_block_index,
                            data_buffer, header.section_size);
                    }
                    // 写入CRC
                    buffer_result |= write_to_data_block(group_ctx, group_ctx->current_block_index,
                        (uint8_t*)&stored_raw_crc, CRC32_SIZE);
                    if (buffer_result < 0) {
                        printf("Error: Failed to buffer block %llu for RS repair\n",
                            (unsigned long long)header.block_id);
                        ret = -1;
                    }
                }
                else {
                    printf("Error: Out of memory buffering block %llu for RS repair\n",
                        (unsigned long long)header.block_id);
                    ret = -1;
                }
                last_group_id = header.block_group_id;
            }
        }
        if (data_buffer) {
            free(data_buffer);
            data_buffer = NULL;
        }

        start_pos = need_resync ?
            block_start_pos + (long long)sizeof(BlockHeader) : archive_tell();
    }
    if (last_group_id != (uint64_t)-1 && group_ctx->total_size > 0) {
        printf("Processing group index %llu\n", last_group_id);
        if (recover_group_with_rs(group_ctx, recovered_archive_write_sink, NULL) < 0) {
            ret = -1;
        }
        reset_data_group_context(group_ctx);
    }
cleanup:
    if (group_ctx) {
        free_data_group_context(group_ctx);
    }
    if (g_vol_read_ctx) {
        volume_read_close(g_vol_read_ctx);
        g_vol_read_ctx = NULL;
    }
    if (g_vol_ctx) {
        volume_close(g_vol_ctx);
        g_vol_ctx = NULL;
    }
    return ret;
}

typedef struct {
    ExtractingFile* files;
    int file_count;
    int file_capacity;
    int extract_all;
    int extracted_count;
    int corrupted_files;
    int file_not_found;
    int total_files;
    int total_dirs;
    int ret;
} RepairedExtractContext;

typedef enum {
    REPAIRED_PARSE_HEADER,
    REPAIRED_PARSE_DATA,
    REPAIRED_PARSE_CRC
} RepairedParseState;

typedef struct {
    RepairedExtractContext* extract_context;
    RepairedParseState state;
    uint8_t raw_header[sizeof(BlockHeader)];
    size_t header_used;
    BlockHeader header;
    uint8_t* data;
    uint32_t data_used;
    uint8_t raw_crc[CRC32_SIZE];
    size_t crc_used;
    int error;
    int resyncing;
    int stream_corrupted;
    uint64_t skipped_bytes;
} RepairedArchiveParser;

int repaired_extract_add_file(RepairedExtractContext* context, const char* filename) {
    if (context->file_count >= context->file_capacity) {
        int new_capacity = context->file_capacity ? context->file_capacity * 2 : 16;
        ExtractingFile* files = (ExtractingFile*)realloc(context->files,
            (size_t)new_capacity * sizeof(ExtractingFile));
        if (!files) {
            return -1;
        }
        context->files = files;
        memset(&context->files[context->file_capacity], 0,
            (size_t)(new_capacity - context->file_capacity) * sizeof(ExtractingFile));
        context->file_capacity = new_capacity;
    }

    ExtractingFile* file = &context->files[context->file_count];
    strncpy(file->filename, filename, MAX_PATH_LEN - 1);
    file->filename[MAX_PATH_LEN - 1] = '\0';
    file->found = 1;
    return context->file_count++;
}

int repaired_extract_select_file(RepairedExtractContext* context, const char* filename,
    int* file_index) {
    *file_index = -1;
    for (int i = 0; i < context->file_count; ++i) {
        if (strcmp(context->files[i].filename, filename) == 0) {
            context->files[i].found = 1;
            *file_index = i;
            return 1;
        }
    }

    if (!context->extract_all) {
        return 0;
    }

    *file_index = repaired_extract_add_file(context, filename);
    return *file_index >= 0 ? 1 : -1;
}

int repaired_extract_open_file(RepairedExtractContext* context, int file_index,
    const BlockHeader* header) {
    ExtractingFile* file = &context->files[file_index];
    int was_open = file->outfile != NULL;
    if (extracting_file_open(file, header) != 0) return -1;
    if (!was_open) context->total_files++;
    return 0;
}

int repaired_extract_complete_file(RepairedExtractContext* context, ExtractingFile* file) {
    int ret = extracting_file_complete(file, &context->extracted_count,
        &context->corrupted_files);
    if (ret != 0) context->ret = -1;
    return 0;
}

int repaired_extract_process_block(RepairedExtractContext* context,
    const uint8_t* raw_header, uint8_t* data, uint32_t stored_raw_crc) {
    BlockHeader header;
    header_be_to_host((const BlockHeader*)raw_header, &header);
    uint32_t stored_crc = be32toh(stored_raw_crc);

    if (header.magic == MAGIC_NUMBER_DIR) {
        context->total_dirs++;
        if (stored_crc != 0) {
            printf("Warning: Directory %s has non-zero CRC 0x%08x\n", header.filename, stored_crc);
            context->ret = -1;
        }
        if (context->extract_all) {
            char dir_path[MAX_PATH_LEN];
            strncpy(dir_path, header.filename, sizeof(dir_path) - 1);
            dir_path[sizeof(dir_path) - 1] = '\0';
            size_t len = strlen(dir_path);
            if (len > 0 && dir_path[len - 1] == '/') {
                dir_path[len - 1] = '\0';
            }
            if (dir_path[0]) {
                create_directories_with_root(g_output_path, dir_path);
            }
        }
        free(data);
        return 0;
    }

    if (header.magic != MAGIC_NUMBER_FILE || (header.flags & FLAG_RS_REDUNDANT)) {
        free(data);
        return 0;
    }

    int file_index;
    int selected = repaired_extract_select_file(context, header.filename, &file_index);
    if (selected < 0) {
        free(data);
        return -1;
    }
    if (!selected) {
        free(data);
        return 0;
    }
    if (repaired_extract_open_file(context, file_index, &header) != 0) {
        free(data);
        return -1;
    }

    ExtractingFile* file = &context->files[file_index];
    if (extracting_file_process_block(file, &header, data, stored_crc) != 0) {
        return -1;
    }

    if (file->current_size >= file->expected_size) {
        return repaired_extract_complete_file(context, file);
    }
    return 0;
}

int repaired_parser_process_block(RepairedArchiveParser* parser) {
    uint32_t raw_crc;
    memcpy(&raw_crc, parser->raw_crc, sizeof(raw_crc));
    int ret = repaired_extract_process_block(parser->extract_context, parser->raw_header,
        parser->data, raw_crc);
    parser->data = NULL;
    parser->data_used = 0;
    parser->header_used = 0;
    parser->crc_used = 0;
    parser->state = REPAIRED_PARSE_HEADER;
    return ret;
}

int repaired_parser_decode_header(RepairedArchiveParser* parser) {
    BlockHeader raw_header;
    memcpy(&raw_header, parser->raw_header, sizeof(raw_header));

    uint32_t magic = be32toh(raw_header.magic);
    if (magic != MAGIC_NUMBER_FILE && magic != MAGIC_NUMBER_DIR) {
        return 0;
    }

    uint32_t stored_crc = be32toh(raw_header.header_crc32);
    uint32_t calculated_crc = crc32_calc(parser->raw_header, sizeof(BlockHeader) - sizeof(uint32_t));
    if (stored_crc != calculated_crc) {
        return 0;
    }

    header_be_to_host(&raw_header, &parser->header);
    if ((parser->header.magic != MAGIC_NUMBER_FILE &&
        parser->header.magic != MAGIC_NUMBER_DIR) ||
        parser->header.section_size > MAX_SECTION_SIZE) {
        return 0;
    }
    return 1;
}

int repaired_parser_header_magic_at(const uint8_t* data) {
    uint32_t raw_magic;
    memcpy(&raw_magic, data, sizeof(raw_magic));
    uint32_t magic = be32toh(raw_magic);
    return magic == MAGIC_NUMBER_FILE || magic == MAGIC_NUMBER_DIR;
}

void repaired_parser_advance_to_header_candidate(RepairedArchiveParser* parser) {
    uint32_t file_magic = htobe32(MAGIC_NUMBER_FILE);
    uint32_t dir_magic = htobe32(MAGIC_NUMBER_DIR);
    const uint8_t* file_magic_bytes = (const uint8_t*)&file_magic;
    const uint8_t* dir_magic_bytes = (const uint8_t*)&dir_magic;
    size_t used = parser->header_used;

    for (size_t offset = 1; offset + sizeof(file_magic) <= used; ++offset) {
        if (repaired_parser_header_magic_at(parser->raw_header + offset)) {
            memmove(parser->raw_header, parser->raw_header + offset, used - offset);
            parser->header_used = used - offset;
            parser->skipped_bytes += offset;
            return;
        }
    }

    size_t keep = used < sizeof(file_magic) - 1 ? used : sizeof(file_magic) - 1;
    while (keep > 0 &&
        memcmp(parser->raw_header + used - keep, file_magic_bytes, keep) != 0 &&
        memcmp(parser->raw_header + used - keep, dir_magic_bytes, keep) != 0) {
        keep--;
    }
    if (keep > 0) {
        memmove(parser->raw_header, parser->raw_header + used - keep, keep);
    }
    parser->header_used = keep;
    parser->skipped_bytes += used - keep;
}

int repaired_parser_feed(RepairedArchiveParser* parser, const uint8_t* data, size_t size) {
    while (size > 0) {
        if (parser->state == REPAIRED_PARSE_HEADER) {
            size_t copy_size = sizeof(BlockHeader) - parser->header_used;
            if (copy_size > size) copy_size = size;
            memcpy(parser->raw_header + parser->header_used, data, copy_size);
            parser->header_used += copy_size;
            data += copy_size;
            size -= copy_size;
            if (parser->header_used != sizeof(BlockHeader)) continue;

            if (!repaired_parser_decode_header(parser)) {
                if (!parser->resyncing) {
                    printf("Warning: Recovered stream lost block alignment; searching for the next valid header\n");
                    parser->resyncing = 1;
                    parser->stream_corrupted = 1;
                    parser->skipped_bytes = 0;
                }
                repaired_parser_advance_to_header_candidate(parser);
                continue;
            }
            if (parser->resyncing) {
                printf("Warning: Recovered stream resynchronized after skipping %llu bytes\n",
                    (unsigned long long)parser->skipped_bytes);
                parser->resyncing = 0;
                parser->skipped_bytes = 0;
            }
            parser->data_used = 0;
            parser->crc_used = 0;
            if (parser->header.section_size == 0) {
                parser->state = REPAIRED_PARSE_CRC;
            }
            else {
                parser->data = (uint8_t*)malloc(parser->header.section_size);
                if (!parser->data) {
                    printf("Error: Out of memory for recovered block data\n");
                    parser->error = -1;
                    return -1;
                }
                parser->state = REPAIRED_PARSE_DATA;
            }
        }
        else if (parser->state == REPAIRED_PARSE_DATA) {
            size_t copy_size = parser->header.section_size - parser->data_used;
            if (copy_size > size) copy_size = size;
            memcpy(parser->data + parser->data_used, data, copy_size);
            parser->data_used += (uint32_t)copy_size;
            data += copy_size;
            size -= copy_size;
            if (parser->data_used == parser->header.section_size) {
                parser->state = REPAIRED_PARSE_CRC;
            }
        }
        else {
            size_t copy_size = CRC32_SIZE - parser->crc_used;
            if (copy_size > size) copy_size = size;
            memcpy(parser->raw_crc + parser->crc_used, data, copy_size);
            parser->crc_used += copy_size;
            data += copy_size;
            size -= copy_size;
            if (parser->crc_used == CRC32_SIZE && repaired_parser_process_block(parser) != 0) {
                parser->error = -1;
                return -1;
            }
        }
    }
    return 0;
}

int repaired_parser_sink(const uint8_t* data, size_t size, void* context) {
    return repaired_parser_feed((RepairedArchiveParser*)context, data, size);
}

int repaired_extract_init(RepairedExtractContext* context, char** files, int file_count) {
    memset(context, 0, sizeof(*context));
    context->extract_all = file_count == 0;
    if (context->extract_all) {
        printf("Extracting all files with RS recovery\n");
        return 0;
    }

    context->files = (ExtractingFile*)calloc(file_count, sizeof(ExtractingFile));
    if (!context->files) {
        return -1;
    }
    context->file_count = file_count;
    context->file_capacity = file_count;
    printf("Extracting selected files with RS recovery:\n");
    for (int i = 0; i < file_count; ++i) {
        strncpy(context->files[i].filename, files[i], MAX_PATH_LEN - 1);
        context->files[i].filename[MAX_PATH_LEN - 1] = '\0';
        printf("  %s\n", context->files[i].filename);
    }
    return 0;
}

int repaired_extract_finish(RepairedExtractContext* context) {
    for (int i = 0; i < context->file_count; ++i) {
        ExtractingFile* file = &context->files[i];
        if (file->outfile) {
            fclose(file->outfile);
            file->outfile = NULL;
            file->corrupted = 1;
            context->corrupted_files++;
            context->ret = -1;
        }
        if (!context->extract_all && !file->found) {
            printf("Warning: File '%s' not found in archive\n", file->filename);
            context->file_not_found++;
            context->ret = -1;
        }
    }

    printf("\nExtraction summary:\n");
    printf("  - Total file in archive: %d\n", context->total_files);
    printf("  - Total directory in archive: %d\n", context->total_dirs);
    printf("  - Successfully extracted: %d\n", context->extracted_count);
    printf("  - Corrupted files: %d\n", context->corrupted_files);
    int ret = context->ret;
    free(context->files);
    context->files = NULL;
    return ret;
}

int extract_archive_with_repair(const char* archive_name, char** files, int file_count) {
    VolumeReadContext vol_ctx;
    DataGroupContext* group_ctx = NULL;
    RepairedExtractContext extract_context;
    RepairedArchiveParser parser;
    int ret = 0;

    if (repaired_extract_init(&extract_context, files, file_count) != 0) {
        printf("Error: Out of memory preparing extraction\n");
        return -1;
    }
    if (g_output_path[0] != '\0') {
        printf("Output directory: %s\n", g_output_path);
        create_directories(g_output_path);
    }
    memset(&parser, 0, sizeof(parser));
    parser.extract_context = &extract_context;
    parser.state = REPAIRED_PARSE_HEADER;
    fec_init();

    if (volume_read_init(&vol_ctx, archive_name) != 0) goto cleanup;
    g_vol_read_ctx = &vol_ctx;
    group_ctx = init_data_group_context();
    if (!group_ctx) goto cleanup;

    printf("Scanning archive and recovering RS groups directly into extracted files...\n");
    long long start_pos = 0;
    long long filesize = vol_ctx.file_size;
    uint64_t block_num = 0;
    uint64_t last_group_id = (uint64_t)-1;

    while (1) {
        long long pos = find_next_magic(vol_ctx.file, start_pos, filesize);
        if (pos == -1) {
            if (volume_read_next(&vol_ctx) != 0) break;
            start_pos = 0;
            filesize = vol_ctx.file_size;
            continue;
        }

        long long block_start_pos = pos;

        BlockHeader header;
        BlockHeader raw_header;
        if (!read_block_header(&header, &raw_header)) {
            start_pos = pos + 1;
            continue;
        }
        validate_block_header(&header, pos, start_pos, &block_num);

        uint8_t* data = NULL;
        uint32_t stored_crc = 0;
        uint32_t stored_raw_crc = 0;
        int block_available = 1;
        int need_resync = 0;
        if (header.magic == MAGIC_NUMBER_FILE && header.section_size > 0) {
            data = (uint8_t*)malloc(header.section_size);
            if (!data) {
                printf("Error: Out of memory reading block %llu\n", (unsigned long long)header.block_id);
                goto cleanup;
            }
            size_t actual_read = archive_read(data, header.section_size);
            if (actual_read != header.section_size) {
                printf("Warning: Short read for block %llu\n", (unsigned long long)header.block_id);
                memset(data + actual_read, 0, header.section_size - actual_read);
                block_available = 0;
                need_resync = 1;
            }
            if (!read_crc32(&stored_crc, &stored_raw_crc)) {
                block_available = 0;
                need_resync = 1;
            }
            if (crc32_calc(data, header.section_size) != stored_crc) {
                /* Keep the header-valid block; chunk CRCs decide which parts
                 * can still be used by RS. */
                need_resync = 1;
            }
        }
        else {
            if (!read_crc32(&stored_crc, &stored_raw_crc)) {
                block_available = 0;
                need_resync = 1;
            }
        }

        if (need_resync && !block_available) {
            free(data);
            data = NULL;
            start_pos = block_start_pos + (long long)sizeof(BlockHeader);
            printf("Resyncing after corrupted block %llu (group %llu) from position 0x%llx\n",
                (unsigned long long)header.block_id,
                (unsigned long long)header.block_group_id,
                (unsigned long long)start_pos);
            continue;
        }

        if (header.block_group_id != 0 && last_group_id != (uint64_t)-1 &&
            header.block_group_id != last_group_id) {
            printf("Processing group index %llu\n", (unsigned long long)last_group_id);
            if (recover_group_with_rs(group_ctx, repaired_parser_sink, &parser) != 0) ret = -1;
            reset_data_group_context(group_ctx);
        }

        if (header.block_group_id == 0) {
            if (repaired_parser_feed(&parser, (const uint8_t*)&raw_header, sizeof(raw_header)) != 0 ||
                (data && repaired_parser_feed(&parser, data, header.section_size) != 0) ||
                repaired_parser_feed(&parser, (const uint8_t*)&stored_raw_crc, CRC32_SIZE) != 0) {
                free(data);
                goto cleanup;
            }
            free(data);
            data = NULL;
        }
        else if (block_available) {
            if (init_data_block(group_ctx, header.block_id,
                header.section_size + sizeof(BlockHeader) + CRC32_SIZE) < 0 ||
                write_to_data_block(group_ctx, group_ctx->current_block_index,
                    (const uint8_t*)&raw_header, sizeof(raw_header)) < 0 ||
                (data && write_to_data_block(group_ctx, group_ctx->current_block_index,
                    data, header.section_size) < 0) ||
                write_to_data_block(group_ctx, group_ctx->current_block_index,
                    (const uint8_t*)&stored_raw_crc, CRC32_SIZE) < 0) {
                printf("Error: Failed to buffer block %llu for RS recovery\n",
                    (unsigned long long)header.block_id);
                free(data);
                goto cleanup;
            }
            last_group_id = header.block_group_id;
            free(data);
            data = NULL;
        }
        else {
            free(data);
            data = NULL;
        }
        start_pos = need_resync ?
            block_start_pos + (long long)sizeof(BlockHeader) : archive_tell();
    }

    if (last_group_id != (uint64_t)-1 && group_ctx->total_size > 0) {
        printf("Processing group index %llu\n", (unsigned long long)last_group_id);
        if (recover_group_with_rs(group_ctx, repaired_parser_sink, &parser) != 0) ret = -1;
    }
    if (parser.error || parser.state != REPAIRED_PARSE_HEADER) {
        printf("Error: Recovered stream ended with an incomplete block\n");
        ret = -1;
    }
    else if (parser.header_used != 0) {
        if (parser.resyncing) {
            printf("Warning: Ignored %llu trailing bytes while searching for a valid block header\n",
                (unsigned long long)(parser.skipped_bytes + parser.header_used));
        }
        else {
            printf("Error: Recovered stream ended with an incomplete block header\n");
        }
        ret = -1;
    }
    if (parser.stream_corrupted) {
        ret = -1;
    }

cleanup:
    free(parser.data);
    if (group_ctx) free_data_group_context(group_ctx);
    if (g_vol_read_ctx) {
        volume_read_close(g_vol_read_ctx);
        g_vol_read_ctx = NULL;
    }
    if (repaired_extract_finish(&extract_context) != 0) ret = -1;
    return ret;
}

// 训练字典函数（修正版 - 支持大文件）
int train_dictionary(const char** file_list, int file_count,
    const char* output_dict_file, size_t max_dict_size) {
    if (file_count < MIN_TRAINING_SAMPLES) {
        printf("Error: Need at least %d files for training (got %d)\n",
            MIN_TRAINING_SAMPLES, file_count);
        return -1;
    }

    printf("Training ZSTD dictionary...\n");
    printf("  - Files: %d\n", file_count);
    printf("  - Max dictionary size: %zu bytes\n", max_dict_size);

    // 统一限制最大2GB
    const size_t MAX_TOTAL_SIZE = 2ULL * 1024 * 1024 * 1024;  // 2GB
    const size_t MAX_SAMPLE_SIZE = 64 * 1024 * 1024;  // 64MB per sample

    // 第一步：获取所有文件大小并计算总大小
    size_t* sample_sizes = (size_t*)malloc(file_count * sizeof(size_t));

    if (!sample_sizes) {
        printf("Error: Out of memory\n");
        return -1;
    }

    size_t total_samples_size = 0;
    int valid_samples = 0;

    printf("Scanning training files...\n");
    for (int i = 0; i < file_count; i++) {
        struct __stat64 st;
        if (stat64_utf8(file_list[i], &st) != 0) {
            printf("Warning: Cannot access file: %s\n", file_list[i]);
            sample_sizes[i] = 0;
            continue;
        }

        // 检查是否为普通文件
        if (!(st.st_mode & _S_IFREG)) {
            printf("Warning: Not a regular file: %s\n", file_list[i]);
            sample_sizes[i] = 0;
            continue;
        }

        // 使用64位文件大小
        uint64_t file_size = st.st_size;

        if (file_size < 1024) {
            printf("Warning: File too small (< 1024 bytes): %s (%llu bytes)\n",
                file_list[i], (unsigned long long)file_size);
            sample_sizes[i] = 0;
            continue;
        }

        // 限制单个样本大小为64MB（避免内存占用过大）
        size_t sample_size = (size_t)(file_size > MAX_SAMPLE_SIZE ?
            MAX_SAMPLE_SIZE : file_size);

        // 检查是否超过2GB限制
        if (total_samples_size + sample_size > MAX_TOTAL_SIZE) {
            printf("Error: Total samples size would exceed 2GB limit\n");
            printf("  Current: %zu bytes (%.2f MB)\n", total_samples_size,
                total_samples_size / (1024.0 * 1024.0));
            printf("  Attempting to add: %zu bytes (%.2f MB)\n", sample_size,
                sample_size / (1024.0 * 1024.0));
            printf("  Limit: 2GB\n");
            printf("Please reduce number of files or use smaller samples.\n");
            free(sample_sizes);
            return -1;
        }

        sample_sizes[i] = sample_size;
        total_samples_size += sample_size;
        valid_samples++;

        printf("  - [%d] %s: %llu bytes -> sample %zu bytes\n",
            valid_samples, file_list[i], (unsigned long long)file_size, sample_size);
    }

    if (valid_samples < MIN_TRAINING_SAMPLES) {
        printf("Error: Only %d valid samples (need %d)\n", valid_samples, MIN_TRAINING_SAMPLES);
        free(sample_sizes);
        return -1;
    }

    printf("  - Valid samples: %d\n", valid_samples);
    printf("  - Total samples size: %zu bytes (%.2f MB)\n",
        total_samples_size, total_samples_size / (1024.0 * 1024.0));

    // 第二步：分配缓冲区并加载所有样本
    uint8_t* samples_buffer = (uint8_t*)malloc(total_samples_size);
    if (!samples_buffer) {
        printf("Error: Out of memory for samples buffer (%zu bytes, %.2f MB)\n",
            total_samples_size, total_samples_size / (1024.0 * 1024.0));
        free(sample_sizes);
        return -1;
    }

    size_t offset = 0;
    int loaded_samples = 0;
    size_t* actual_sizes = (size_t*)malloc(file_count * sizeof(size_t));
    if (!actual_sizes) {
        printf("Error: Out of memory\n");
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    printf("Loading samples into memory...\n");

    for (int i = 0; i < file_count; i++) {
        if (sample_sizes[i] == 0) {
            actual_sizes[loaded_samples] = 0;
            continue;
        }

        FILE* f = fopen_utf8(file_list[i], "rb");
        if (!f) {
            printf("Warning: Cannot open file: %s\n", file_list[i]);
            actual_sizes[loaded_samples] = 0;
            continue;
        }

        size_t remaining = sample_sizes[i];
        size_t file_offset = 0;
        size_t read_size;

        // 读取样本数据（分块读取，避免单次读取过大）
        while (remaining > 0) {
            size_t chunk_size = remaining > (16 * 1024 * 1024) ? (16 * 1024 * 1024) : remaining;
            read_size = fread(samples_buffer + offset + file_offset, 1, chunk_size, f);

            if (read_size == 0) {
                if (ferror(f)) {
                    printf("Warning: Read error for %s at offset %zu\n", file_list[i], file_offset);
                }
                break;
            }

            file_offset += read_size;
            remaining -= read_size;
        }
        fclose(f);

        if (file_offset < 1024) {
            // 读取的数据太少，跳过这个样本
            printf("Warning: Too little data read from %s (%zu bytes), skipping\n",
                file_list[i], file_offset);
            actual_sizes[loaded_samples] = 0;
            continue;
        }

        // 更新实际读取的大小
        actual_sizes[loaded_samples] = file_offset;

        printf("  - [%d] Loaded: %s (%zu bytes)\n", loaded_samples + 1, file_list[i], file_offset);

        offset += file_offset;
        loaded_samples++;
    }

    valid_samples = loaded_samples;
    total_samples_size = offset;

    if (valid_samples < MIN_TRAINING_SAMPLES) {
        printf("Error: Only %d samples loaded successfully (need %d)\n",
            valid_samples, MIN_TRAINING_SAMPLES);
        free(actual_sizes);
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    printf("  - Loaded %d samples, total: %zu bytes (%.2f MB)\n",
        valid_samples, total_samples_size, total_samples_size / (1024.0 * 1024.0));

    // 第三步：训练字典
    uint8_t* dict_buffer = (uint8_t*)malloc(max_dict_size);
    if (!dict_buffer) {
        printf("Error: Out of memory for dictionary buffer\n");
        free(actual_sizes);
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    printf("Training dictionary (this may take a while)...\n");

    size_t dict_size = ZDICT_trainFromBuffer(
        dict_buffer, max_dict_size,
        samples_buffer,       // 单个连续缓冲区
        actual_sizes,         // 每个样本的大小数组
        valid_samples         // 样本数量
    );

    if (ZDICT_isError(dict_size)) {
        printf("Error: Dictionary training failed: %s\n", ZDICT_getErrorName(dict_size));
        free(dict_buffer);
        free(actual_sizes);
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    // 第四步：保存字典
    FILE* out = fopen_utf8(output_dict_file, "wb");
    if (!out) {
        printf("Error: Cannot create dictionary file: %s\n", output_dict_file);
        free(dict_buffer);
        free(actual_sizes);
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    size_t written = fwrite(dict_buffer, 1, dict_size, out);
    fclose(out);

    if (written != dict_size) {
        printf("Error: Failed to write dictionary file (wrote %zu, expected %zu)\n",
            written, dict_size);
        free(dict_buffer);
        free(actual_sizes);
        free(samples_buffer);
        free(sample_sizes);
        return -1;
    }

    uint32_t dict_id = calculate_dict_id(dict_buffer, dict_size);

    printf("\nDictionary trained successfully:\n");
    printf("  - Size: %zu bytes (%.2f KB)\n", dict_size, dict_size / 1024.0);
    printf("  - ID: 0x%08x\n", dict_id);
    printf("  - Samples used: %d\n", valid_samples);
    printf("  - Total sample data: %zu bytes (%.2f MB)\n",
        total_samples_size, total_samples_size / (1024.0 * 1024.0));
    printf("  - Saved to: %s\n", output_dict_file);

    // 清理
    free(dict_buffer);
    free(actual_sizes);
    free(samples_buffer);
    free(sample_sizes);

    return 0;
}

void print_usage(const char* progname) {
    printf("LLawsXX Archive Tool (lxar) - Windows Version (with AES encryption, ZSTD compression, multi-volume and RS redundancy support)\n");
    printf("Usage:\n");
    printf("  %s archive [-o <output_file>] [-s <size>] [-v <size>] [-p <password>] [-z <level>] [-d <dict>] [--rs <data> <parity> | --rs-size <size>] [--rs-group-size <size>] <file_or_directory>   - Create archive\n", progname);
    printf("  %s extract [--repair] [-o <output_dir>] [-p <password>] [-d <dict>] <archive>       - Extract all files\n", progname);
    printf("  %s extract [--repair] [-o <output_dir>] [-p <password>] [-d <dict>] <archive> <files> - Extract specific files\n", progname);
    printf("  %s list <archive>                     - List archive contents\n", progname);
    printf("  %s verify [-p <password>] <archive>                   - Verify archive integrity\n", progname);
    printf("  %s repair [-o <output>] <archive>                    - Repair corrupted archive\n", progname);
    printf("  %s train-dict -o <dict_file> [-s <max_size>] <files...>  - Train ZSTD dictionary\n", progname);
    printf("\nOptions:\n");
    printf("  -o, --output <path>        Set output file/directory path\n");
    printf("  -s, --section-size <size>  Set section size (default: 256K)\n");
    printf("                              Supported suffixes: K, M, G\n");
    printf("  -v, --volume-size <size>   Set volume size for multi-volume archives\n");
    printf("                              Supported suffixes: K, M, G, T (e.g., 100M, 1G, 4G)\n");
    printf("                              Use -v 0 or omit for single file archive\n");
    printf("                              Supports up to %d volumes\n", MAX_VOLUME_NUMBER);
    printf("  -p, --password <password>   Set encryption password (AES-128 CBC)\n");
    printf("                              Password can be 16 hex bytes (32 chars) or any string\n");
    printf("  -z, --compress <level>      Set ZSTD compression level (1-22, default: 3)\n");
    printf("                              Use -z 0 to disable compression\n");
    printf("  -d, --dict <file>           Use ZSTD dictionary for compression/decompression\n");
    printf("                              Dictionary can be trained with the train-dict command\n");
    printf("  --repair                     Recover RS groups while extracting; no repaired archive is created\n");
    printf("  --index                      Scan and sort valid blocks by block_id before extraction\n");
    printf("  --rs <data> <parity>        Enable Reed-Solomon redundancy (up to 256 total shards; GF(2^8))\n");
    printf("  --rs-size <size>             Enable fixed-size RS redundancy per group (e.g. 50M; conflicts with --rs)\n");
    printf("  --rs-group-size <size>      Set RS group size (default: 512M, maximum: 16G)\n");
    printf("\nDictionary Training:\n");
    printf("  train-dict -o <dict_file> [-s <max_size>] <files...>\n");
    printf("      Train a ZSTD dictionary from sample files\n");
    printf("      -o <dict_file> : Output dictionary file (required)\n");
    printf("      -s <max_size>  : Maximum dictionary size (default: 128K)\n");
    printf("                       Supported suffixes: K, M\n");
    printf("      <files...>     : Training sample files (minimum %d required)\n", MIN_TRAINING_SAMPLES);
    printf("      Note: For best results, provide samples similar to the data you'll compress.\n");
    printf("            Total sample size should be ~100x the target dictionary size.\n");
    printf("\nFeatures:\n");
    printf("  - Supports empty directories\n");
    printf("  - Supports empty files (0 bytes)\n");
    printf("  - ZSTD compression (configurable level)\n");
    printf("  - ZSTD dictionary compression for better ratios on similar data\n");
    printf("  - AES-128 CBC encryption (data only, headers remain unencrypted)\n");
    printf("  - Multi-volume support (automatic splitting, up to %d volumes)\n", MAX_VOLUME_NUMBER);
    printf("  - Reed-Solomon erasure coding for data recovery\n");
    printf("  - Each section uses its header CRC as IV\n");
    printf("\nExamples:\n");
    printf("  # Basic archive creation\n");
    printf("  %s archive myfile.txt\n", progname);
    printf("  %s archive myfolder\n", progname);
    printf("  %s archive -o myarchive.lxar myfolder\n", progname);
    printf("  %s archive -s 1M -v 100M -p mypassword -z 5 -o encrypted_compressed.lxar myfolder\n", progname);
    printf("\n  # Multi-volume archives\n");
    printf("  %s archive -v 1G myfolder                    # Split into 1GB volumes\n", progname);
    printf("  %s archive -v 4T myfolder                    # Split into 4TB volumes (large archives)\n", progname);
    printf("  %s archive -v 0 myfolder                      # Single file archive (default)\n", progname);
    printf("\n  # Compression options\n");
    printf("  %s archive -z 0 myfolder                      # Disable compression\n", progname);
    printf("  %s archive -z 12 myfolder                     # High compression level\n", progname);
    printf("\n  # Dictionary-based compression\n");
    printf("  %s train-dict -o mydict.zstd sample1.txt sample2.txt sample3.txt\n", progname);
    printf("  %s archive -d mydict.zstd -z 12 -o compressed.lxar myfolder\n", progname);
    printf("  %s extract -d mydict.zstd -p password compressed.lxar\n", progname);
    printf("\n  # Reed-Solomon redundancy\n");
    printf("  %s archive --rs 10 3 myfolder                 # Add 3 parity blocks for every 10 data blocks\n", progname);
    printf("  %s archive --rs 10 3 --rs-group-size 200M myfolder\n", progname);
    printf("  %s archive --rs-size 50M myfolder             # Target about 50MB redundancy per RS group\n", progname);
    printf("\n  # Encryption\n");
    printf("  %s archive -p mypassword myfolder\n", progname);
    printf("  %s archive -p 00112233445566778899aabbccddeeff -o key.lxar myfolder\n", progname);
    printf("\n  # Extraction\n");
    printf("  %s extract -o extracted_files -p mypassword myfolder.lxar\n", progname);
    printf("  %s extract --repair -o restored damaged.lxar\n", progname);
    printf("  %s extract -o output_dir archive.lxar file1.txt file2.txt\n", progname);
    printf("  %s extract -o output_dir -p pass -d dict.zstd archive.lxar\n", progname);
    printf("\n  # Verification and repair\n");
    printf("  %s verify -p mypassword archive.lxar\n", progname);
    printf("  %s repair -o repaired.lxar corrupted.lxar\n", progname);
    printf("\nMulti-volume naming:\n");
    printf("  Files are named as: basename.001.lxar (1-999)\n");
    printf("                     basename.1000.lxar (1000-9999)\n");
    printf("                     basename.10000.lxar (10000-99999)\n");
    printf("                     basename.100000.lxar (100000 and above)\n");
    printf("  When extracting, specify the first volume (e.g., archive.001.lxar)\n");
}




int _main(int argc, char* argv[]) {
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
        int volume_index = -1;
        int dict_index = -1;
        int rs_data = -1;
        int rs_parity = -1;
        int rs_group_size_index = -1;
        int rs_size_index = -1;

        // 检查是否有各种选项
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--section-size") == 0) {
                if (i + 1 < argc) {
                    g_section_size = parse_section_size(argv[i + 1]);
                    i++;
                }
            }
            else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--volume-size") == 0) {
                if (i + 1 < argc) {
                    volume_index = i + 1;
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
            else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dict") == 0) {
                if (i + 1 < argc) {
                    dict_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "--rs") == 0) {
                if (i + 2 < argc) {
                    rs_data = atoi(argv[i + 1]);
                    rs_parity = atoi(argv[i + 2]);
                    i += 2;
                }
            }
            else if (strcmp(argv[i], "--rs-size") == 0) {
                if (i + 1 < argc) {
                    rs_size_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "--rs-group-size") == 0) {
                if (i + 1 < argc) {
                    rs_group_size_index = i + 1;
                    i++;
                }
            }
            else {
                dir_index = i;
                break;
            }
        }

        // 处理分卷大小
        if (volume_index != -1) {
            g_volume_size = parse_volume_size(argv[volume_index]);
            if (g_volume_size > 0) {
                printf("Multi-volume mode enabled, volume size: %llu bytes\n", (unsigned long long)g_volume_size);
                printf("Maximum volumes supported: %d\n", MAX_VOLUME_NUMBER);
            }
            else {
                printf("Single file mode (no splitting)\n");
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

        // 处理字典文件
        if (dict_index != -1) {
            if (load_dict_from_file(argv[dict_index]) != 0) {
                printf("Warning: Failed to load dictionary, will use normal compression\n");
                g_warning_count++;
            }
        }

        // 处理密码
        if (password_index != -1) {
            generate_key_from_password(argv[password_index]);
        }

        // 冗余设置
        if (rs_size_index != -1 && (rs_data != -1 || rs_parity != -1)) {
            printf("Error: --rs-size conflicts with --rs\n");
            return 1;
        }

        if (rs_data > 0 && rs_parity > 0) {
            uint64_t total_rs_shards = (uint64_t)(unsigned int)rs_data + (uint64_t)(unsigned int)rs_parity;
            if (total_rs_shards <= 256) {
                g_rs_enabled = 1;
                g_rs_data_shards = rs_data;
                g_rs_parity_shards = rs_parity;
                g_current_block_group_index = 1;
                printf("RS redundancy enabled: %d data shards, %d parity shards (GF(2^8))\n",
                    rs_data, rs_parity);
            }
            else {
                printf("RS redundancy not enabled: %d data shards + %d parity shards larger than 256\n",
                    rs_data, rs_parity);
            }
        }
        else if (rs_size_index != -1) {
            g_rs_fixed_size = parse_size(argv[rs_size_index]);
            if (g_rs_fixed_size == 0) {
                printf("Error: --rs-size must be greater than zero\n");
                return 1;
            }
            g_rs_enabled = 1;
            g_rs_fixed_size_enabled = 1;
            g_current_block_group_index = 1;
            printf("RS redundancy enabled: target %llu bytes per group, "
                "dynamic shard counts (up to 256 total, GF(2^8))\n",
                (unsigned long long)g_rs_fixed_size);
        }

        if (rs_group_size_index != -1) {
            g_rs_group_size = parse_rs_group_size(argv[rs_group_size_index]);
            printf("RS group size: %llu bytes\n", (unsigned long long)g_rs_group_size);
        }

        // 找到输入文件或目录参数
        if (dir_index >= argc) {
            printf("Error: Missing input file or directory\n");
            print_usage(argv[0]);
            return 1;
        }

        char archive_name[PATH_LEN_FOR_PROC];
        if (output_index != -1) {
            // 使用指定的输出文件名
            strncpy(archive_name, argv[output_index], sizeof(archive_name) - 1);
            archive_name[sizeof(archive_name) - 1] = '\0';
        }
        else {
            // 使用默认输出文件名
            snprintf(archive_name, sizeof(archive_name), "%s.lxar", get_last_path_component(argv[dir_index]));
        }

        int result = create_archive(archive_name, argv[dir_index]);

        // 清理字典上下文
        if (g_dict_ctx) {
            free_dict_context(g_dict_ctx);
            g_dict_ctx = NULL;
        }

        return result;
    }
    else if (strcmp(argv[1], "extract") == 0 && argc >= 3) {
        // 解析extract命令的参数
        int archive_index = 2;
        int password_index = -1;
        int output_index = -1;
        int dict_index = -1;
        int repair_while_extracting = 0;
        int index_before_extracting = 0;

        // 检查是否有-p和-o和--dict选项
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
            else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dict") == 0) {
                if (i + 1 < argc) {
                    dict_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "--repair") == 0) {
                repair_while_extracting = 1;
            }
            else if (strcmp(argv[i], "--index") == 0) {
                index_before_extracting = 1;
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

        // 处理字典文件
        if (dict_index != -1) {
            if (load_dict_from_file(argv[dict_index]) != 0) {
                printf("Error: Failed to load dictionary required for extraction\n");
                return 1;
            }
        }

        // 处理输出路径
        if (output_index != -1) {
            strncpy(g_output_path, argv[output_index], PATH_LEN_FOR_PROC - 1);
            g_output_path[PATH_LEN_FOR_PROC - 1] = '\0';
            // 创建输出目录
            create_directories(g_output_path);
        }

        int result;
        if (index_before_extracting) {
            result = extract_archive_indexed(argv[archive_index],
                archive_index + 1 < argc ? &argv[archive_index + 1] : NULL,
                argc - archive_index - 1, repair_while_extracting);
        }
        else if (repair_while_extracting) {
            result = extract_archive_with_repair(argv[archive_index],
                archive_index + 1 < argc ? &argv[archive_index + 1] : NULL,
                argc - archive_index - 1);
        }
        else if (archive_index + 1 < argc) {
            // 有指定文件列表
            result = extract_archive(argv[archive_index], &argv[archive_index + 1], argc - archive_index - 1);
        }
        else {
            // 提取所有文件
            result = extract_archive(argv[archive_index], NULL, 0);
        }

        // 清理字典上下文
        if (g_dict_ctx) {
            free_dict_context(g_dict_ctx);
            g_dict_ctx = NULL;
        }

        return result;
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
    else if (strcmp(argv[1], "repair") == 0 && argc >= 3) {
        int archive_index = 2;
        int output_index = -1;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
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

        if (archive_index >= argc) {
            printf("Error: Missing archive name\n");
            print_usage(argv[0]);
            return 1;
        }

        char repaired_archive_name[PATH_LEN_FOR_PROC];
        if (output_index != -1) {
            strncpy(repaired_archive_name, argv[output_index], sizeof(repaired_archive_name) - 1);
            repaired_archive_name[sizeof(repaired_archive_name) - 1] = '\0';
        }
        else {
            snprintf(repaired_archive_name, sizeof(repaired_archive_name), "%s.repaired", get_last_path_component(argv[archive_index]));
        }

        return repair_archive(argv[archive_index], repaired_archive_name);
    }
    else if (strcmp(argv[1], "train-dict") == 0) {
        // train-dict命令：训练字典
        // 用法: lxar train-dict -o <dict_file> [-s <max_size>] <files...>

        int output_index = -1;
        int size_index = -1;
        int compress_index = -1;
        size_t max_dict_size = 128 * 1024; // 默认128KB
        int file_start = -1;

        // 解析选项
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                if (i + 1 < argc) {
                    output_index = i + 1;
                    i++;
                }
            }
            else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--max-size") == 0) {
                if (i + 1 < argc) {
                    size_index = i + 1;
                    i++;
                }
            }
            else {
                file_start = i;
                break;
            }
        }

        // 验证必需参数
        if (output_index == -1) {
            printf("Error: Missing output file (-o <dict_file>)\n");
            printf("Usage: %s train-dict -o <dict_file> [-s <max_size>] <files...>\n", argv[0]);
            return 1;
        }

        if (file_start == -1 || file_start >= argc) {
            printf("Error: No training files specified\n");
            printf("Usage: %s train-dict -o <dict_file> [-s <max_size>] <files...>\n", argv[0]);
            return 1;
        }

        // 处理字典大小限制
        if (size_index != -1) {
            max_dict_size = parse_size(argv[size_index]);
            if (max_dict_size > MAX_DICT_SIZE) {
                printf("Warning: Requested dictionary size %zu exceeds maximum %d, using %d\n",
                    max_dict_size, MAX_DICT_SIZE, MAX_DICT_SIZE);
                max_dict_size = MAX_DICT_SIZE;
            }
            if (max_dict_size < 1024) {
                printf("Warning: Requested dictionary size %zu too small, using minimum 1024 bytes\n",
                    max_dict_size);
                max_dict_size = 1024;
            }
        }

        // 获取文件列表
        int file_count = argc - file_start;

        printf("=== ZSTD Dictionary Training ===\n");
        printf("Output file: %s\n", argv[output_index]);
        printf("Max dictionary size: %zu bytes (%.2f KB)\n", max_dict_size, max_dict_size / 1024.0);
        printf("Number of training files: %d\n", file_count);
        printf("================================\n\n");

        // 调用训练函数
        int result = train_dictionary((const char**)&argv[file_start], file_count,
            argv[output_index], max_dict_size);

        if (result == 0) {
            printf("\nDictionary training completed successfully!\n");
            printf("You can now use it with:\n");
            printf("  %s archive --dict %s <directory>\n", argv[0], argv[output_index]);
        }
        else {
            printf("\nDictionary training failed!\n");
        }

        return result;
    }
    else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}


int main() {
    SetConsoleOutputCP(CP_UTF8);
    // 获取 UTF-16 格式的命令行
    int ret = 0;
    int argc;
    LPWSTR cmdLine = GetCommandLineW();
    LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);
    char** utf8_argv = NULL;

    if (!argv) {
        fprintf(stderr, "Failed to parse command line\n");
        ret = -1;
        goto end;
    }

    utf8_argv = calloc(argc, sizeof(char*));

    if (!utf8_argv) {
        fprintf(stderr, "Failed to malloc utf8_argv\n");
        ret = -1;
        goto end;
    }

    for (int i = 0; i < argc; i++) {
        char* utf8_arg = utf16_to_utf8(argv[i]);

        if (utf8_arg) {
            utf8_argv[i] = utf8_arg;
            printf("argv[%d]: %s\n", i, utf8_arg);
        }
        else {
            printf("argv[%d]: <conversion failed>\n", i);
            ret = -1;
            goto end;
        }
    }

    ret = _main(argc, utf8_argv);

    // 释放 CommandLineToArgvW 分配的内存
end:
    if (utf8_argv)
    {
        for (int i = 0; i < argc; i++) {
            if (utf8_argv[i]) {
                free(utf8_argv[i]);
            }
        }
        free(utf8_argv);
    }
    if (argv)
        LocalFree(argv);
    return ret;
}
