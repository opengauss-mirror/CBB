/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * compress.c
 *    compress process
 *
 * IDENTIFICATION
 *    src/cm_compress/cm_compress.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_compress.h"
#include "cm_file.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif

static LZ4F_preferences_t g_kPrefs = {
    { LZ4F_max256KB, LZ4F_blockLinked, LZ4F_noContentChecksum, LZ4F_frame, 0, 0, LZ4F_noBlockChecksum },
    1, 0, 0, { 0, 0, 0 },
};

status_t lz4f_alloc(compress_t *ctx)
{
    size_t ret;

    if (ctx->is_compress) {
        ret = LZ4F_createCompressionContext(&(ctx->lz4f_cstream), LZ4F_VERSION);
    } else {
        ret = LZ4F_createDecompressionContext(&(ctx->lz4f_dstream), LZ4F_VERSION);
    }

    if (LZ4F_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "lz4f", ret, LZ4F_getErrorName(ret));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lz4f_init(compress_t *ctx)
{
    // lz4's compression will init the resource in the end of each subtask automatically,
    // so we do not need to do the initialization of compression here
    if (!ctx->is_compress) {
        LZ4F_resetDecompressionContext(ctx->lz4f_dstream);
    }

    return CM_SUCCESS;
}

status_t cm_compress_init(compress_t *ctx)
{
    ctx->in_chunk_size = 0;
    ctx->write_len = 0;
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            return lz4f_init(ctx);
        default:
            break;
    }

    return CM_SUCCESS;
}

static status_t lz4f_compress(compress_t *ctx, char *write_buf, size_t write_buf_len)
{
    size_t remain_size = ctx->in_chunk_size;
    size_t copy_size;
    /* stream data */
    do {
        copy_size = MIN(IN_CHUNK_SIZE, remain_size);
        size_t res = LZ4F_compressUpdate(ctx->lz4f_cstream,
                                         ctx->out_buf, ctx->out_buf_capacity,
                                         ctx->in_buf + ctx->in_chunk_size - remain_size, copy_size, NULL);
        if (LZ4F_isError(res)) {
            CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
            return CM_ERROR;
        }

        if (res != 0) {
            errno_t ret = memcpy_sp(write_buf + ctx->write_len, write_buf_len - ctx->write_len, ctx->out_buf, res);
            MEMS_RETURN_IFERR(ret);
        }
        ctx->write_len += res;
        remain_size -= copy_size;
    } while (remain_size != 0);

    return CM_SUCCESS;
}

static status_t lz4f_compress_end(compress_t *ctx)
{
    size_t res = LZ4F_compressEnd(ctx->lz4f_cstream, ctx->out_buf, ctx->out_buf_capacity, NULL);
    if (LZ4F_isError(res)) {
        CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return CM_ERROR;
    }

    ctx->write_len += res;

    return CM_SUCCESS;
}

status_t lz4f_decompress(compress_t *ctx, char *write_buf, size_t *write_buf_len)
{
    size_t buf_size = *write_buf_len;
    size_t copy_size;
    size_t remain_size = ctx->in_chunk_size;

    do {
        copy_size = MIN(IN_CHUNK_SIZE, remain_size);
        const void* src_ptr = (const char*)ctx->in_buf + ctx->in_chunk_size - remain_size;
        const void * const src_end = (const char*)src_ptr + copy_size;

        while (src_ptr < src_end) {
            /* Any data within dst has been flushed at this stage */
            size_t dst_size = ctx->out_buf_capacity;
            size_t src_size = (const char*)src_end - (const char*)src_ptr;
            size_t ret = LZ4F_decompress(ctx->lz4f_dstream, ctx->out_buf, &dst_size, src_ptr, &src_size, NULL);
            if (LZ4F_isError(ret)) {
                CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", ret, LZ4F_getErrorName(ret));
                return CM_ERROR;
            }
            if (dst_size != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(write_buf + ctx->write_len, buf_size - ctx->write_len,
                    ctx->out_buf, dst_size));
            }
            ctx->write_len += dst_size;
            src_ptr = (const char*)src_ptr + src_size;
        }

        CM_ASSERT(src_ptr == src_end);
        remain_size -= copy_size;
    } while (remain_size);

    *write_buf_len = ctx->write_len;

    return CM_SUCCESS;
}

status_t cm_decompress_stream(compress_t *ctx, char *write_buf, size_t *buf_len)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            return lz4f_decompress(ctx, write_buf, buf_len);
        default:
            break;
    }

    return CM_SUCCESS;
}

status_t cm_compress_begin(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            g_kPrefs.compressionLevel = ctx->level;
            size_t header_size = LZ4F_compressBegin(ctx->lz4f_cstream, ctx->out_buf, ctx->out_buf_capacity, &g_kPrefs);
            if (LZ4F_isError(header_size)) {
                CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", header_size, LZ4F_getErrorName(header_size));
                return CM_ERROR;
            }
            ctx->write_len = header_size;
            break;
        default:
            return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_compress_flush(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            if (lz4f_compress_end(ctx) != CM_SUCCESS) {
                return CM_ERROR;
            }
            break;
        default:
            return CM_ERROR;
    }
    return CM_SUCCESS;
}


status_t cm_compress_stream(compress_t *ctx, char *write_buf, size_t write_buf_len)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            return lz4f_compress(ctx, write_buf, write_buf_len);
        default:
            break;
    }

    return CM_SUCCESS;
}

/*
 * Alloc resource needed by compression or decompression.
 * @param the attributes of backup or restore
 * @param compress context
 * @param the action is backup or restore
 * @return
 * - CM_SUCCESS
 * _ CM_ERROR
 * @note must call in the begining of the backup or restore task
 */
status_t cm_compress_alloc(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            return lz4f_alloc(ctx);
        default:
            break;
    }

    return CM_SUCCESS;
}

status_t cm_compress_alloc_buff(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            ctx->in_buf_capacity = IN_CHUNK_SIZE;
            ctx->out_buf_capacity = LZ4F_compressBound(IN_CHUNK_SIZE, &g_kPrefs);
            break;
        default:
            return CM_ERROR;
    }
    ctx->in_buf_capacity = MAX(ctx->in_buf_capacity, ctx->frag_size);
    ctx->in_buf = (char *)malloc(ctx->in_buf_capacity);
    if (ctx->in_buf == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)ctx->in_buf_capacity, "compress in buffer memory");
        return CM_ERROR;
    }
    ctx->out_buf = (char *)malloc(ctx->out_buf_capacity);
    if (ctx->out_buf == NULL) {
        CM_FREE_PTR(ctx->in_buf);
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)ctx->out_buf_capacity, "compress out buffer memory");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void lz4f_end(compress_t *zctx)
{
    size_t ret;
    if (zctx->is_compress) {
        ret = LZ4F_freeCompressionContext(zctx->lz4f_cstream);
    } else {
        ret = LZ4F_freeDecompressionContext(zctx->lz4f_dstream);
    }

    zctx->lz4f_cstream = NULL;

    if (LZ4F_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_FREE_ERROR, "LZ4F", ret, LZ4F_getErrorName(ret));
    }
}

/*
 * Free the resource of the compression or decompression.
 * @param the attributes of backup or restore
 * @param compress context
 * @param the action is backup or restore
 * @return
 * - CM_SUCCESS
 * _ CM_ERROR
 * @note must call in the end of the backup or restore task
 */
void cm_compress_free(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_LZ4:
            lz4f_end(ctx);
            break;
        default:
            break;
    }
}

#ifdef __cplusplus
}
#endif
