#define _CRT_SECURE_NO_WARNINGS
/*
 * lxar - LLawsXX ARchive format - Windows版本 (支持AES加密、ZSTD压缩和分卷)
 *
 *
 * 使用方法:
 *   lxar archive [-o <输出文件>] [-s <size>] [-v <size>] [-p <password>] [-z <level>] <目录>        - 创建归档
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
#include "rs.h"
#include <windows.h>
#include <direct.h>
#include <zstd.h>
#include <errno.h>

#define DEFAULT_SECTION_SIZE (256 * 1024)  // 默认256KB
#define MIN_SECTION_SIZE (1024)            // 最小1KB
#define MAX_SECTION_SIZE (64 * 1024 * 1024) // 最大64MB
#define MIN_RS_GROUP_SIZE (1 * 1024 * 1024) //最小1MB
#define MAX_RS_GROUP_SIZE (1024 * 1024 * 1024) // 最大1024MB

#define DEFAULT_VOLUME_SIZE (0)            // 默认不分卷
#define MIN_VOLUME_SIZE (4 * 1024 * 1024)  // 最小分卷大小4MB
#define MAX_VOLUME_SIZE (4LL * 1024 * 1024 * 1024 * 1024) // 最大4TB
#define MAX_VOLUME_NUMBER 99999             // 最大分卷编号支持到99999

#define MAGIC_NUMBER_FILE 0x424C4F43  // "BLOC" in ASCII
#define MAGIC_NUMBER_DIR 0x44495200   // "DIR\0" in ASCII
#define MAX_PATH_LEN MAX_PATH
#define CRC32_SIZE 4

 // 标志位定义
#define FLAG_ENCRYPTED 0x01  // 数据已加密
#define FLAG_COMPRESSED 0x02  // 数据已压缩 (ZSTD)
#define FLAG_RS_REDUNDANT 0x04  // RS冗余块

// 默认压缩级别
#define DEFAULT_COMPRESSION_LEVEL 3

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
    uint32_t total_size;
} DataGroupContext;


typedef struct ReassembledBlock {
    uint64_t block_index;      // 原始block索引
    uint32_t block_offset;   //在Block数据中的偏移
    uint32_t original_offset;   //在原数据中的偏移
    uint32_t size;              // 重组块的实际大小
    uint32_t crc32;
    struct ReassembledBlock* next;
} ReassembledBlock;


typedef struct {
    uint8_t* data;
    uint32_t total_size;        // 重组数据总大小
    uint32_t split_size;        // 分割大小
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
char g_output_path[MAX_PATH] = { 0 }; // 输出路径
// 添加全局变量来保存输入根路径
const char* g_input_root_path = NULL;
int g_error_count = 0;           // 错误计数
int g_warning_count = 0;         // 警告计数
uint64_t g_current_block_index = 0;   // 当前块索引计数器
uint64_t g_current_block_group_index = 0;   // 当前块组索引计数器

// RS冗余相关全局变量
int g_rs_enabled = 0;                // 是否启用RS冗余
int g_rs_data_shards = 0;            // RS数据分片数
int g_rs_parity_shards = 0;          // RS校验分片数
uint64_t g_rs_group_size = 256 * 1024 * 1024;
int g_use_rs_recovery = 0;  // 是否使用RS冗余恢复

// 函数声明
size_t archive_write(const void* ptr, size_t size, int next_volume_if_needed,int is_write_rs);
size_t archive_read(void* ptr, size_t size);
int archive_seek(long long offset, int origin);
long long archive_tell(void);
int rs_group_write(ReassembledContext* ctx, int parity_shards_count, uint64_t group_index);

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

    printf("DataGroupContext: total_size = %u\n", context->total_size);
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


ReassembledBlock* create_reassembled_block(uint64_t block_index, uint32_t block_offset, uint32_t original_offset, uint32_t size, uint32_t crc32) {
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

void add_reassembled_block_info(ReassembledContext* ctx, uint64_t block_index, uint32_t block_offset,
    uint32_t original_offset, uint32_t size, uint32_t crc32) {
    if (ctx == NULL) return;

    ReassembledBlock* new_block = create_reassembled_block(block_index, block_offset, original_offset, size, crc32);
    if (new_block == NULL) return;

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
}

ReassembledContext* reassemble_data_by_size(DataGroupContext* context, uint32_t split_size) {
    if (context == NULL || context->front == NULL || split_size == 0) {
        return NULL;
    }

    // 计算总数据大小
    uint32_t total_data_size = context->total_size;
    if (total_data_size == 0) {
        return NULL;
    }

    // 分配重组后的数据缓冲区
    uint8_t* reassembled_data = (uint8_t*)malloc(total_data_size);
    if (reassembled_data == NULL) {
        return NULL;
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
    uint32_t current_offset = 0;
    DataBlock* current_block = context->front;

    while (current_block != NULL && current_block->size > 0) {
        if (current_block->data != NULL) {
            memcpy(reassembled_data + current_offset, current_block->data, current_block->size);
            current_offset += current_block->size;
        }
        current_block = current_block->next;
    }

    // 第二步：构建原始块在重组缓冲区中的位置映射
    typedef struct {
        uint64_t block_index;
        uint32_t reassembled_offset;  // 在重组缓冲区中的起始偏移
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
    BlockMapping* mappings = (BlockMapping*)malloc(sizeof(BlockMapping) * block_count);
    if (mappings == NULL) {
        free(reassembled_data);
        free(result);
        return NULL;
    }

    // 填充映射信息
    uint32_t mapping_idx = 0;
    uint32_t offset = 0;
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
    uint32_t reassembled_offset = 0;
    uint32_t remaining_data = total_data_size;

    while (remaining_data > 0) {
        uint32_t current_split_size = (remaining_data > split_size) ? split_size : remaining_data;

        // 计算当前重组块在重组缓冲区中的范围
        uint32_t segment_start = reassembled_offset;
        uint32_t segment_end = reassembled_offset + current_split_size - 1;

        // 遍历所有原始块，找出与当前重组块有重叠的原始块
        for (uint32_t i = 0; i < block_count; i++) {
            uint32_t block_start = mappings[i].reassembled_offset;
            uint32_t block_end = mappings[i].reassembled_offset + mappings[i].size - 1;

            // 检查是否有重叠
            if (segment_start >= block_start && segment_start <= block_end) {
                // 计算在原始块中的偏移
                uint32_t block_offset = segment_start - block_start;

                uint32_t crc32 = crc32_calc(reassembled_data + segment_start, current_split_size);
                // 记录重组块信息
                add_reassembled_block_info(result, mappings[i].block_index, block_offset,
                    segment_start, current_split_size, crc32);
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
uint32_t calculate_split_size_by_count(uint32_t total_size, uint32_t split_count) {
    if (split_count == 0) {
        return 0;
    }

    // 计算基础切割大小
    uint32_t base_size = (total_size + split_count - 1) / split_count;
    return base_size;
}


ReassembledContext* reassemble_data_by_count(DataGroupContext* context, uint32_t split_count) {
    if (context == NULL || context->front == NULL || split_count == 0) {
        return NULL;
    }

    // 计算总数据大小
    uint32_t total_data_size = context->total_size;
    if (total_data_size == 0) {
        return NULL;
    }

    // 根据总大小和切割份数计算切割大小
    uint32_t split_size = calculate_split_size_by_count(total_data_size, split_count);

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
    printf("║ Total size: %-10u bytes    Split size: %-10u bytes    ║\n",
        ctx->total_size, ctx->split_size);
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
            printf("│   [%d] block_index=%-8llu block offset=%-8u offset=%-8u size=%-8u    │\n",
                ref_index, (unsigned long long)current->block_index , current->block_offset,
                current->original_offset, current->size);
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
        if (ret < 0) return ret;
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
        ReassembledContext* split_info = reassemble_data_by_count(g_group_ctx, g_rs_data_shards);
        //print_reassembled_info(split_info);
        printf("Writing RS data group %llu\n", g_current_block_group_index);
        if (rs_group_write(split_info, g_rs_parity_shards, g_current_block_group_index) < 0) {
            printf("Error: Writing RS data group %llu failed\n", g_current_block_group_index);
        }

        free_reassembled_info(split_info);
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
        if (ret < 0) return ret;
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
uint32_t parse_rs_group_size(const char* size_str) {
    uint64_t size = parse_size(size_str);

    // 检查范围
    if (size < MIN_RS_GROUP_SIZE) {
        printf("Warning: RS group size too small (%llu bytes), using minimum %d bytes\n",
            size, MIN_RS_GROUP_SIZE);
        size = MIN_RS_GROUP_SIZE;
    }
    else if (size > MAX_RS_GROUP_SIZE) {
        printf("Warning: RS group size too large (%llu bytes), using maximum %d bytes\n",
            size, MAX_RS_GROUP_SIZE);
        size = MAX_RS_GROUP_SIZE;
    }
    return (uint32_t)size;
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

    vol->current_file = fopen(vol_name, "wb");
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
    ctx->file = fopen(archive_name, "rb");
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

    ctx->file = fopen(next_vol, "rb");
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
    if (_stat64(dirpath, &st) != 0) {
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
    char relative_path[MAX_PATH_LEN] = { 0 };
    if (get_relative_path(filepath, g_input_root_path, relative_path, sizeof(relative_path)) != 0) {
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
            if (g_compression_enabled && compressed_len > 0) header.flags |= FLAG_COMPRESSED;
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
    if(g_rs_enabled)
        fec_init();
    int ret = 0;
    // 检查输入路径是否存在
    if (!is_directory(input_path)) {
        printf("Error: Input path does not exist: %s\n", input_path);
        ret = -1;
        goto end;
    }

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
    static char input_root[MAX_PATH];
    strncpy(input_root, input_path, MAX_PATH - 1);
    input_root[MAX_PATH - 1] = '\0';
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
    else {
        printf("Creating archive: %s\n", archive_name);
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

    // Windows下使用自定义目录遍历，先处理目录，再处理文件
    walk_directory(input_path, process_file, process_directory);

    if (g_rs_enabled && g_group_ctx && g_group_ctx->total_size > 0) {
        //print_data_group_context(g_group_ctx);
        ReassembledContext* split_info = reassemble_data_by_count(g_group_ctx, g_rs_data_shards);
        //print_reassembled_info(split_info);
        printf("Writing RS data group %llu\n", g_current_block_group_index);
        if (rs_group_write(split_info, g_rs_parity_shards, g_current_block_group_index) < 0) {
            printf("Error: Writing RS data group %llu failed\n", g_current_block_group_index);
        }
        free_reassembled_info(split_info);
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
                char flags_str[32] = "";
                if (header.flags & FLAG_ENCRYPTED) strcat(flags_str, "encrypted ");
                if (header.flags & FLAG_COMPRESSED) strcat(flags_str, "compressed");

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
                // 第一次遇到这个文件，打开输出文件
                char output_file_path[MAX_PATH];
                build_output_path(g_output_path, header.filename, output_file_path, sizeof(output_file_path));

                printf("Extracting: %s", header.filename);
                if (header.flags & FLAG_ENCRYPTED) printf(" (encrypted)");
                if (header.flags & FLAG_COMPRESSED) printf(" (compressed)");
                printf("\n");

                // 创建文件所在的目录
                char* dir_path = strdup(output_file_path);
                char* dir = dirname(dir_path);
                if (strcmp(dir, ".") != 0 && strcmp(dir, "\\") != 0 && strlen(dir) > 0) {
                    create_directories(dir);
                }
                free(dir_path);

                // 打开输出文件
                extracting_files[file_index].outfile = fopen(output_file_path, "wb");
                if (!extracting_files[file_index].outfile) {
                    printf("Error: Cannot create file %s\n", output_file_path);
                    ret = -1;
                    goto cleanup;
                }

                extracting_files[file_index].expected_size = header.total_size;
                extracting_files[file_index].current_size = 0;
                extracting_files[file_index].expected_section_id = 0;
                extracting_files[file_index].total_sections = header.total_section_count;
                extracting_files[file_index].is_encrypted = (header.flags & FLAG_ENCRYPTED) ? 1 : 0;
                extracting_files[file_index].is_compressed = (header.flags & FLAG_COMPRESSED) ? 1 : 0;
                extracting_files[file_index].corrupted = 0;

                // 初始化进度显示
                progress_init(&extracting_files[file_index].progress,
                    header.total_size,
                    header.total_section_count,
                    header.filename);
            }

            if (file_index >= 0 && extracting_files[file_index].outfile) {
                // 处理这个块的数据
                ExtractingFile* ef = &extracting_files[file_index];

                // 检查section_id
                if (header.section_id != ef->expected_section_id) {
                    printf("Warning: File '%s' section id mismatch: expected %llu, found %llu\n",
                        ef->filename, ef->expected_section_id, header.section_id);
                    ef->corrupted = 1;
                }

                // 检查data_offset
                if (header.data_offset != ef->current_size) {
                    printf("Warning: File '%s' data offset mismatch: expected %llu, found %llu\n",
                        ef->filename, ef->current_size, header.data_offset);
                    ef->corrupted = 1;
                    if (header.data_offset < header.total_size) {
                        printf("Seeking to expected offset\n");
                        if (_fseeki64(ef->outfile, header.data_offset, SEEK_SET) != 0) {
                            printf("Seek failed, error code: %d\n", errno);
                        }
                        else {
                            ef->current_size = header.data_offset;
                        }
                    }
                }

                uint32_t original_len = header.original_size;
                uint32_t data_len = header.section_size;

                // 处理数据
                if (data_len > 0) {
                    // 计算CRC
                    CRC32_Context ctx;
                    crc32_init(&ctx);

                    // 读取数据
                    uint8_t* data_buffer = (uint8_t*)malloc(data_len);
                    if (!data_buffer) {
                        printf("Error: Out of memory allocating %u bytes\n", data_len);
                        ret = -1;
                        goto cleanup;
                    }

                    size_t actual_read = archive_read(data_buffer, data_len);
                    if (actual_read != data_len) {
                        printf("Error: Failed to read data for %s, expected %u bytes, got %zu\n",
                            ef->filename, data_len, actual_read);
                        ef->corrupted = 1;
                        memset(data_buffer + actual_read, 0, data_len - actual_read);
                    }

                    // 更新CRC
                    crc32_update(&ctx, data_buffer, data_len);

                    // 如果需要解密
                    if (header.flags & FLAG_ENCRYPTED) {
                        if (g_encryption_enabled) {
                            if (data_len % AES_BLOCK_SIZE != 0) {
                                printf("Warning: Section size is not a multiple of AES_BLOCK_SIZE\n");
                            }
                            process_data_block(data_buffer, data_len, header.header_crc32, 0);
                            uint32_t unpadded_len;
                            if (pkcs7_unpad(data_buffer, data_len, &unpadded_len) < 0) {
                                printf("Error: PKCS#7 unpad failed\n");
                                ef->corrupted = 1;
                            }
                            else {
                                data_len = unpadded_len;
                            }
                        }
                        else {
                            printf("Error: The file is encrypted, but no password provided\n");
                        }
                    }

                    // 如果需要解压缩
                    uint8_t* final_data = data_buffer;
                    uint32_t final_len = data_len;

                    if (header.flags & FLAG_COMPRESSED) {
                        uint8_t* decompressed = decompress_zstd(data_buffer, data_len, original_len);
                        if (!decompressed) {
                            printf("Error: Decompression failed for %s section id %llu\n",
                                ef->filename, (unsigned long long)header.section_id);
                            ef->corrupted = 1;
                        }
                        else {
                            free(data_buffer);
                            final_data = decompressed;
                            final_len = original_len;
                        }
                    }

                    // 写入文件
                    size_t write_len = final_len > original_len ? original_len : final_len;
                    size_t actual_write = fwrite(final_data, 1, write_len, ef->outfile);

                    if (actual_write != write_len) {
                        printf("Error: Failed to write data for %s section id %llu\n",
                            ef->filename, (unsigned long long)header.section_id);
                        free(final_data);
                        ret = -1;
                        goto cleanup;
                    }

                    // 如果写入长度小于预期，需要seek
                    if (write_len < original_len) {
                        printf("Seeking past the end of file %llu bytes\n", original_len - write_len);
                        if (_fseeki64(ef->outfile, original_len - write_len, SEEK_CUR) != 0) {
                            printf("Seek failed, error code: %d\n", errno);
                        }
                    }

                    free(final_data);

                    // 读取存储的CRC
                    uint32_t stored_crc;
                    read_crc32(&stored_crc,NULL);

                    // 验证CRC
                    uint32_t crc = crc32_final(&ctx);
                    if (crc != stored_crc) {
                        printf("Error: File %s section id %llu CRC check failed\n",
                            ef->filename, (unsigned long long)header.section_id);
                        printf("       Calculated: 0x%08x, Stored: 0x%08x\n", crc, stored_crc);
                        ef->corrupted = 1;
                    }

                    ef->current_size += original_len;
                    ef->expected_section_id = header.section_id + 1;

                    // 更新进度
                    progress_update(&ef->progress, ef->current_size, header.section_id, 0);
                }
                else {
                    // 空文件，跳过CRC
                    uint32_t stored_crc;
                    read_crc32(&stored_crc,NULL);
                    if (stored_crc != 0) {
                        printf("Warning: Empty file %s has non-zero CRC 0x%08x\n",
                            ef->filename, stored_crc);
                    }
                    ef->current_size = 0;
                }

                // 检查文件是否完成
                if (ef->current_size >= ef->expected_size) {
                    progress_finish(&ef->progress);
                    fclose(ef->outfile);
                    ef->outfile = NULL;

                    if (ef->corrupted) {
                        corrupted_files++;
                        char new_file_name[MAX_PATH];
                        char original_path[MAX_PATH];
                        build_output_path(g_output_path, ef->filename, original_path, sizeof(original_path));
                        snprintf(new_file_name, sizeof(new_file_name), "%s.corrupted", original_path);
                        printf("File %s corrupted, rename to %s\n", ef->filename, new_file_name);
                        if (rename(original_path, new_file_name) != 0) {
                            printf("File %s rename to %s failed\n", ef->filename, new_file_name);
                        }
                    }
                    else {
                        extracted_count++;
                        char flags_str[32] = "";
                        if (ef->is_encrypted && g_encryption_enabled) strcat(flags_str, "decrypted");
                        if (ef->is_compressed) {
                            if (strlen(flags_str) > 0) strcat(flags_str, " ");
                            strcat(flags_str, "decompressed");
                        }
                        if (strlen(flags_str) > 0) {
                            printf("Successfully extracted: %s (%llu bytes) (%s)\n",
                                ef->filename, ef->expected_size, flags_str);
                        }
                        else {
                            printf("Successfully extracted: %s (%llu bytes)\n",
                                ef->filename, ef->expected_size);
                        }
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
                char new_file_name[MAX_PATH];
                char original_path[MAX_PATH];
                build_output_path(g_output_path, ef->filename, original_path, sizeof(original_path));
                snprintf(new_file_name, sizeof(new_file_name), "%s.corrupted", original_path);

                printf("\nFile %s was incomplete (expected %llu bytes, got %llu), rename to %s\n",
                    extracting_files[i].filename,
                    extracting_files[i].expected_size,
                    extracting_files[i].current_size, new_file_name
                );
                if (rename(original_path, new_file_name) != 0) {
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
int rs_group_write(ReassembledContext* ctx, int parity_shards_count, uint64_t group_index) {
    if (!ctx || ctx->data == NULL) return -1;

    uint32_t max_block_size = ctx->split_size;
    int data_shards_count = 0;
    ReassembledBlock* current = ctx->block_info;

    while (current != NULL) {
        data_shards_count++;
        current = current->next;
    }

    // 初始化指针
    reed_solomon* rs = NULL;
    uint8_t** data_shards = NULL;
    uint8_t** parity_shards = NULL;
    uint8_t* rs_data = NULL;
    int ret = -1;

    // 为RS编码准备数据
    data_shards = (uint8_t**)calloc(data_shards_count, sizeof(uint8_t*));
    parity_shards = (uint8_t**)calloc(parity_shards_count, sizeof(uint8_t*));

    if (!data_shards || !parity_shards) {
        goto cleanup;
    }

    current = ctx->block_info;
    int i = 0;
    while (current != NULL) {
        data_shards[i] = (uint8_t*)calloc(max_block_size, 1);
        if (!data_shards[i]) {
            goto cleanup;
        }
        memcpy(data_shards[i], &ctx->data[current->original_offset], current->size);
        current = current->next;
        i++;
    }

    // 初始化校验分片
    for (int i = 0; i < parity_shards_count; i++) {
        parity_shards[i] = (uint8_t*)calloc(max_block_size, 1);
        if (!parity_shards[i]) {
            goto cleanup;
        }
    }

    // 创建RS编码器
    rs = reed_solomon_new(data_shards_count, parity_shards_count);
    if (!rs) {
        ret = -1;
        goto cleanup;
    }

    // 执行编码
    int encode_result = reed_solomon_encode(rs, data_shards, parity_shards, max_block_size);
    if (encode_result != 0) {
        ret = -1;
        goto cleanup;
    }

    // 计算并写入RS冗余块
    uint64_t total_section_count = parity_shards_count;

    for (int i = 0; i < parity_shards_count; i++) {
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
        rs_header.chunk_count = ctx->block_count;
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
        current = ctx->block_info;
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
    if (rs) {
        reed_solomon_release(rs);
    }

    if (rs_data) {
        free(rs_data);
    }

    if (data_shards) {
        for (int i = 0; i < data_shards_count; i++) {
            if (data_shards[i]) {
                free(data_shards[i]);
            }
        }
        free(data_shards);
    }

    if (parity_shards) {
        for (int i = 0; i < parity_shards_count; i++) {
            if (parity_shards[i]) {
                free(parity_shards[i]);
            }
        }
        free(parity_shards);
    }

    return ret;
}

// 解析RS块信息（从内存中解析）
int parse_rs_block_info(uint8_t* rs_data, size_t rs_size, RSDataChunkInfo** chunks,
    int* chunk_count, uint32_t* shard_size) {
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

    *chunk_count = header.chunk_count;
    *shard_size = header.data_size;
    *chunks = (RSDataChunkInfo*)malloc(header.chunk_count * sizeof(RSDataChunkInfo));
    if (!*chunks) {
        return -1;
    }

    uint8_t* ptr = rs_data + sizeof(RSBlockHeader);
    for (int i = 0; i < header.chunk_count; i++) {
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
    RSDataChunkInfo* chunks;    // 分片信息
    int chunk_count;            // 分片信息数量
} RSShardsInfo;

// 释放RSShardsInfo
void free_rs_shards_info(RSShardsInfo* rs_info) {
    int nr_shards = rs_info->data_shards_count + rs_info->parity_shards_count;
    if (rs_info->shards) {
        for (int i = 0; i < nr_shards; i++) {
            if (rs_info->shards[i]) free(rs_info->shards[i]);
        }
        free(rs_info->shards);
    }

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
    nr_shards = data_shards_count + (int)parity_shards_count;

    shards = (uint8_t**)calloc(nr_shards, sizeof(uint8_t*));
    marks = (uint8_t*)calloc(nr_shards, sizeof(uint8_t));

    if (!shards || !marks) {
        printf("Out of memory for shard arrays\n");
        goto cleanup;
    }

    // 初始化所有分片缓冲区
    for (int i = 0; i < nr_shards; i++) {
        shards[i] = (uint8_t*)calloc(shard_size, 1);
        if (!shards[i]) {
            printf("Out of memory for shard %d\n", i);
            goto cleanup;
        }
    }

    for (int i = 0; i < nr_shards; i++) {
        marks[i] = 1;
    }

    // 第四步：从数据块中填充数据分片
    for (int i = 0; i < chunk_count; i++) {
        for (int j = 0; j < data_block_count; j++) {
            RepairBlockInfo* block = &data_blocks[j];
            if (chunks[i].block_index == block->block_id) {
                uint32_t remaining = chunks[i].size;
                uint32_t offset = chunks[i].offset;
                uint32_t shard_offset = 0;
                int j2 = j;
                while (remaining > 0 && j2 < data_block_count) {
                    block = &data_blocks[j2];
                    uint32_t read_size = remaining > block->block_size - offset ? block->block_size - offset : remaining;
                    memcpy(shards[i] + shard_offset, block->data + offset, read_size);
                    remaining -= read_size;
                    shard_offset += read_size;
                    j2++;
                    offset = 0;
                }
                uint32_t crc32 = crc32_calc(shards[i], chunks[i].size);
                if (crc32 == chunks[i].crc32) {
                    marks[i] = 0;
                }
                break;
            }
        }
    }

    // 第五步：从RS块中填充校验分片
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

        if (rs_data_size >= shard_size) {
            memcpy(shards[(int)rs_block->section_id + data_shards_count], rs_data_start, shard_size);
            marks[(int)rs_block->section_id + data_shards_count] = 0;
        }
        else {
            printf("  Warning: RS block %llu has insufficient data\n", rs_block->block_id);
        }
    }


    // 填充输出结构
    rs_info->shards = shards;
    rs_info->marks = marks;
    rs_info->data_shards_count = data_shards_count;
    rs_info->parity_shards_count = (int)parity_shards_count;
    rs_info->shard_size = shard_size;
    rs_info->chunks = chunks;
    rs_info->chunk_count = chunk_count;

    // 释放临时数组（不释放分片数据）
    free(data_blocks);
    free(rs_blocks);
    return 0;

cleanup:
    if (shards) {
        // 清理已分配的分片
        for (int i = 0; i < nr_shards; i++) {
            if (shards[i]) free(shards[i]);
        }
        free(shards);
    }
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

// 恢复group
int recover_group_with_rs_and_write(DataGroupContext* group_ctx) {
    if (!group_ctx) {
        return -1;
    }
    RSShardsInfo rs_info;
    int ret = 0;
    if (extract_rs_shards_from_group(group_ctx, &rs_info) != 0) {
        DataBlock* current = group_ctx->front;
        while (current != NULL) {
            if (current->data && current->size > 0) {
                size_t written = archive_write(current->data, current->size, 0, 0);
                if (written != current->size) {
                    printf("  Warning: Failed to write block id %llu (size=%u)\n",current->block_index, current->size);
                    ret = -1;
                }
            }
            current = current->next;
        }
        return ret;
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
        reed_solomon* rs = reed_solomon_new(rs_info.data_shards_count, rs_info.parity_shards_count);
        if (rs) {
            // 执行RS解码
            printf("Reconstructing missing chunks\n");
            int decode_result = reed_solomon_reconstruct(rs, rs_info.shards, rs_info.marks, total_shards, rs_info.shard_size);

            if (decode_result == 0) {
                printf("RS reconstruction successful!\n");
            }
            else {
                printf("RS reconstruction failed with error code: %d\n", decode_result);
                ret = -1;
            }

            // 清理资源
            reed_solomon_release(rs);
        }
        else {
            printf("Failed to create RS decoder\n");
            ret = -1;
        }
    }

    for (int i = 0; i < rs_info.data_shards_count; i++) {
        uint32_t size = rs_info.chunks[i].size;
        size_t written = archive_write(rs_info.shards[i], size, 0, 0);
        if (written != size) {
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

        if (header.magic == MAGIC_NUMBER_FILE && header.section_size > 0) {
            // 读取数据
            data_buffer = (uint8_t*)malloc(data_len);
            if (data_buffer) {
                size_t actual_read = archive_read(data_buffer, data_len);
                if (actual_read != data_len) {
                    printf("Warning: Short read for block %llu (expected %u, got %zu)\n",
                        (unsigned long long)header.block_id, data_len, actual_read);
                    if(header.flags & FLAG_RS_REDUNDANT) //冗余块不允许损坏
                        block_available = 0;
                }
                else {
                    // 计算CRC
                    CRC32_Context crc_ctx;
                    crc32_init(&crc_ctx);
                    crc32_update(&crc_ctx, data_buffer, data_len);
                    uint32_t calc_crc = crc32_final(&crc_ctx);

                    // 读取存储的CRC
                    read_crc32(&stored_crc,&stored_raw_crc);

                    if (calc_crc != stored_crc) {
                        printf("Warning: CRC mismatch for block %llu (group %llu): calc=0x%08x, stored=0x%08x\n",
                            (unsigned long long)header.block_id,
                            (unsigned long long)header.block_group_id,
                            calc_crc, stored_crc);
                        //有可能只坏了部分，重组shards的时候会再计算一次CRC，可能这个block整体数据不正确，但部分数据是正确的
                        //所以不标记block_corrupted（但冗余块不允许损坏）
                        if (header.flags & FLAG_RS_REDUNDANT)
                            block_available = 0;
                    }
                }
            }
            else {
                printf("Warning: Out of memory for block %llu\n",
                    (unsigned long long)header.block_id);
                block_available = 0;
            }
        }
        else if (header.magic == MAGIC_NUMBER_FILE && header.section_size == 0) {
            // 空文件，只读取CRC
            read_crc32(&stored_crc, &stored_raw_crc);
            if (stored_crc != 0) {
                printf("Warning: Empty file %s has non-zero CRC 0x%08x\n",
                    header.filename, stored_crc);
            }
        }
        else if (header.magic == MAGIC_NUMBER_DIR) {
            // 目录块，只读取CRC
            read_crc32(&stored_crc, &stored_raw_crc);
            if (stored_crc != 0) {
                printf("Warning: Directory %s has non-zero CRC 0x%08x\n",
                    header.filename, stored_crc);
            }
        }

        if (block_available) {
            // group_id大于0的组才会有冗余数据
            if (header.block_group_id == 0) {
                size_t written = write_block_header(&header, 0);
                if (written != sizeof(BlockHeader)) {
                    printf("  Warning: Failed to write block id %llu header\n", header.block_id);
                }
                if (data_buffer) {
                    written = archive_write(data_buffer, header.section_size,0,0);
                    if (written != header.section_size) {
                        printf("  Warning: Failed to write block id %llu data\n", header.block_id);
                    }
                }
                written = write_crc32(stored_crc, 0);
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
                    if (recover_group_with_rs_and_write(group_ctx) < 0) {
                        ret = -1;
                    }
                    reset_data_group_context(group_ctx);
                }
                if (init_data_block(group_ctx, header.block_id, header.section_size + sizeof(BlockHeader) + CRC32_SIZE) >= 0) {
                    //TODO 一次写入？
                    write_to_data_block(group_ctx, group_ctx->current_block_index, (uint8_t*)&raw_header, sizeof(BlockHeader));
                    if (data_buffer) {
                        write_to_data_block(group_ctx, group_ctx->current_block_index,
                            data_buffer, header.section_size);
                    }
                    // 写入CRC
                    write_to_data_block(group_ctx, group_ctx->current_block_index,
                        (uint8_t*)&stored_raw_crc, CRC32_SIZE);
                }
                last_group_id = header.block_group_id;
            }
        }
        if (data_buffer) {
            free(data_buffer);
            data_buffer = NULL;
        }

        start_pos = archive_tell();
    }
    if (last_group_id != (uint64_t)-1 && group_ctx->total_size > 0) {
        printf("Processing group index %llu\n", last_group_id);
        if (recover_group_with_rs_and_write(group_ctx) < 0) {
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

// 打印使用帮助
void print_usage(const char* progname) {
    printf("LLawsXX Archive Tool (lxar) - Windows Version (with AES encryption, ZSTD compression, multi-volume and RS redundancy support)\n");
    printf("Usage:\n");
    printf("  %s archive [-o <output_file>] [-s <size>] [-v <size>] [-p <password>] [-z <level>] [--rs <data> <parity>] [--rs-group-size <size>] <directory>   - Create archive\n", progname);
    printf("  %s extract [-o <output_dir>] [-p <password>] <archive>                  - Extract all files\n", progname);
    printf("  %s extract [-o <output_dir>] [-p <password>] <archive> <files>          - Extract specific files\n", progname);
    printf("  %s list <archive>                     - List archive contents\n", progname);
    printf("  %s verify [-p <password>] <archive>                   - Verify archive integrity\n", progname);
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
    printf("  --rs <data> <parity>        Enable Reed-Solomon redundancy (data + parity shards)\n");
    printf("  --rs-group-size <size>      Set RS group size (default: 100M)\n");
    printf("\nFeatures:\n");
    printf("  - Supports empty directories\n");
    printf("  - Supports empty files (0 bytes)\n");
    printf("  - ZSTD compression (configurable level)\n");
    printf("  - AES-128 CBC encryption (data only, headers remain unencrypted)\n");
    printf("  - Multi-volume support (automatic splitting, up to %d volumes)\n", MAX_VOLUME_NUMBER);
    printf("  - Reed-Solomon erasure coding for data recovery\n");
    printf("  - Each section uses its header CRC as IV\n");
    printf("\nExamples:\n");
    printf("  %s archive myfolder\n", progname);
    printf("  %s archive -o myarchive.lxar myfolder\n", progname);
    printf("  %s archive -s 1M -v 100M -p mypassword -z 5 -o encrypted_compressed.lxar myfolder\n", progname);
    printf("  %s archive -v 1G myfolder                    # Split into 1GB volumes\n", progname);
    printf("  %s archive -v 4T myfolder                    # Split into 4TB volumes (large archives)\n", progname);
    printf("  %s archive -v 0 myfolder                      # Single file archive (default)\n", progname);
    printf("  %s archive -z 0 myfolder                      # Disable compression\n", progname);
    printf("  %s archive --rs 10 3 myfolder                 # Add 3 parity blocks for every 10 data blocks\n", progname);
    printf("  %s archive --rs 10 3 --rs-group-size 200M myfolder\n", progname);
    printf("  %s archive -p 00112233445566778899aabbccddeeff -o key.lxar myfolder\n", progname);
    printf("  %s extract -o extracted_files -p mypassword myfolder.lxar\n", progname);
    printf("  %s extract -o output_dir archive.lxar file1.txt file2.txt\n", progname);
    printf("\nMulti-volume naming:\n");
    printf("  Files are named as: basename.001.lxar (1-999)\n");
    printf("                     basename.1000.lxar (1000-9999)\n");
    printf("                     basename.10000.lxar (10000-99999)\n");
    printf("                     basename.100000.lxar (100000 and above)\n");
    printf("  When extracting, specify the first volume (e.g., archive.001.lxar)\n");
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
        int volume_index = -1;
        int rs_data = -1;
        int rs_parity = -1;
        int rs_group_size_index = -1;

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
            else if (strcmp(argv[i], "--rs") == 0) {
                if (i + 2 < argc) {
                    rs_data = atoi(argv[i + 1]);
                    rs_parity = atoi(argv[i + 2]);
                    i += 2;
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

        // 处理密码
        if (password_index != -1) {
            generate_key_from_password(argv[password_index]);
        }
        // 冗余设置
        if (rs_data > 0 && rs_parity > 0) {
            g_rs_enabled = 1;
            g_rs_data_shards = rs_data;
            g_rs_parity_shards = rs_parity;
            g_current_block_group_index = 1;
            printf("RS redundancy enabled: %d data shards, %d parity shards\n", rs_data, rs_parity);
        }

        if (rs_group_size_index != -1) {
            g_rs_group_size = parse_rs_group_size(argv[rs_group_size_index]);
            printf("RS group size: %llu bytes\n", (unsigned long long)g_rs_group_size);
        }
        // 找到目录参数
        if (dir_index >= argc) {
            printf("Error: Missing directory name\n");
            print_usage(argv[0]);
            return 1;
        }

        char archive_name[MAX_PATH_LEN];
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
    }else if (strcmp(argv[1], "repair") == 0 && argc >= 3) {
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

        char repaired_archive_name[MAX_PATH_LEN];
        if (output_index != -1) {
            strncpy(repaired_archive_name, argv[output_index], sizeof(repaired_archive_name) - 1);
            repaired_archive_name[sizeof(repaired_archive_name) - 1] = '\0';
        }
        else {
            snprintf(repaired_archive_name, sizeof(repaired_archive_name), "%s.repaired", get_last_path_component(argv[archive_index]));
        }

        return repair_archive(argv[archive_index], repaired_archive_name);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}