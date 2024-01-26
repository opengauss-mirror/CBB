/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
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
 * cm_config.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_config.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_config.h"
#include "cm_hash.h"
#include "cm_error.h"

#ifndef WIN32
#include <termios.h>
#else
#include <conio.h>
#endif  // !WIN32

#ifdef __cplusplus
extern "C" {
#endif

static spinlock_t g_config_lock = 0;
static status_t cm_read_config_file(
    const char *file_name, char *buf, uint32 *buf_len, bool32 is_ifile, bool32 read_only);
static status_t cm_parse_config(config_t *config, char *buf, uint32 buf_len, bool32 is_ifile, bool32 set_alias);

static status_t cm_alloc_config_buf(config_t *config, uint32 size, char **buf)
{
    CM_ASSERT(config != NULL && buf != NULL);
    errno_t errcode = 0;
    if (config->value_buf == NULL) {
        if (config->value_buf_size == 0) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)config->value_buf_size, "config value");
            return CM_ERROR;
        }
        config->value_buf = (char *)cm_malloc_prot(config->value_buf_size);
        if (config->value_buf == NULL) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)config->value_buf_size, "config value");
            return CM_ERROR;
        }
        errcode = memset_sp(config->value_buf, (size_t)config->value_buf_size, 0, (size_t)config->value_buf_size);
        if (errcode != EOK) {
            CM_FREE_PROT_PTR(config->value_buf);
            CM_THROW_ERROR(ERR_RESET_MEMORY, "config->value_buf");
            return CM_ERROR;
        }
    }
    size = CM_ALIGN4(size);
    if (config->value_offset + size > config->value_buf_size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, config->value_offset + size, config->value_buf_size);
        CM_FREE_PROT_PTR(config->value_buf);
        return CM_ERROR;
    }

    *buf = config->value_buf + config->value_offset;
    config->value_offset += size;
    return CM_SUCCESS;
}

config_item_t *cm_get_config_item(const config_t *config, text_t *name, bool32 set_alias)
{
    uint32 hash_value;
    config_item_t *item = NULL;

    CM_ASSERT(config != NULL);
    CM_ASSERT(name != NULL);

    hash_value = cm_hash_bytes((uint8 *)name->str, name->len, CM_CONFIG_HASH_BUCKETS);
    item = config->name_map[hash_value];

    while (item != NULL) {
        if (cm_text_str_equal_ins(name, item->name)) {
            if (set_alias) {
                item->hit_alias = CM_FALSE;
            }
            return item;
        }

        item = item->hash_next;
    }
    hash_value = cm_hash_bytes((uint8 *)name->str, name->len, CM_CONFIG_ALIAS_HASH_BUCKETS);
    item = config->alias_map[hash_value];
    while (item != NULL) {
        if (cm_text_str_equal_ins(name, item->alias)) {
            if (set_alias) {
                item->hit_alias = CM_TRUE;
            }
            return item;
        }

        item = item->hash_next2;
    }
    return NULL;
}

char *cm_get_config_value(const config_t *config, const char *name)
{
    config_item_t *item = NULL;
    text_t text;
    errno_t rc_memzero;

    rc_memzero = (int)memset_sp(&text, sizeof(text_t), 0, sizeof(text_t));
    if (rc_memzero != EOK) {
        return NULL;
    }

    CM_ASSERT(config != NULL);

    cm_str2text((char *)name, &text);
    item = cm_get_config_item(config, &text, CM_FALSE);
    if (item == NULL) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, name);
        return NULL;
    }
    if (item->is_default) {
        return item->default_value;
    }
    return item->value;
}

static status_t cm_get_fullpath(config_t *config, text_t *filepath, char *fullpath, uint32 len)
{
    text_t text;
    char buf[CM_FILE_NAME_BUFFER_SIZE];
    bool32 is_fullpath = (CM_TEXT_FIRST(filepath) == '/' || CM_TEXT_FIRST(filepath) == '\\');
#ifdef WIN32
    is_fullpath = is_fullpath || (cm_get_first_pos(filepath, ':') != CM_INVALID_ID32);
#endif
    if (!is_fullpath) {
        text.str = buf;
        text.len = 0;
        CM_RETURN_IFERR(cm_concat_string(&text, CM_FILE_NAME_BUFFER_SIZE, config->file_name));
        text.len = cm_get_last_pos(&text, '/');
        if ((text.len == CM_INVALID_ID32) || (text.len + filepath->len + 1 >= len)) {
            return CM_ERROR;
        }
        text.len++;
        cm_concat_text(&text, CM_FILE_NAME_BUFFER_SIZE, filepath);
        buf[text.len] = '\0';
    } else {
        CM_RETURN_IFERR(cm_text2str(filepath, buf, sizeof(buf)));
    }

#ifdef WIN32
    (void)_fullpath(fullpath, buf, len);
#else
    char resolved_path[PATH_MAX];
    uint32 path_len;
    errno_t errcode;
    if (realpath(buf, resolved_path) == NULL) {
        CM_THROW_ERROR(ERR_INVALID_FILE_NAME, buf, PATH_MAX);
        return CM_ERROR;
    }
    path_len = (uint32)strlen(resolved_path);
    if (path_len >= len) {
        CM_THROW_ERROR(ERR_INVALID_FILE_NAME, resolved_path, len);
        return CM_ERROR;
    }
    errcode = strncpy_s(fullpath, (size_t)len, resolved_path, (size_t)path_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

static void cm_set_config_ifile_inner(config_t *config, config_item_t *ifile)
{
    if (config->first_file == NULL) {
        config->first_file = ifile;
        config->last_file = ifile;
    } else {
        config->last_file->next_file = ifile;
        config->last_file = ifile;
    }
}

static status_t cm_set_config_ifile(config_t *config, text_t *value, config_item_t **item)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char file_buf[CM_MAX_CONFIG_FILE_SIZE];
    uint32 buf_len = (uint32)sizeof(file_buf);
    config_item_t *ifile = NULL;

    /* get full file path */
    if (cm_get_fullpath(config, value, file_name, (uint32)sizeof(file_name)) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (cm_read_config_file(file_name, file_buf, &buf_len, CM_TRUE, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (cm_alloc_config_buf(config, (uint32)sizeof(config_item_t), (char **)&ifile) != CM_SUCCESS) {
        return CM_ERROR;
    }
    ifile->name = (char *)"IFILE";
    ifile->is_default = CM_FALSE;
    ifile->attr = ATTR_READONLY;
    ifile->flag = FLAG_NONE;
    ifile->next = ifile->next_file = NULL;
    (*item) = ifile;

    /* check if ifile already exists */
    config_item_t *next_file = config->first_file;
    while (next_file != NULL) {
        if (cm_str_equal_ins(next_file->value, file_name)) {
            CM_THROW_ERROR(ERR_INVALID_VALUE, file_name);
            return CM_ERROR;
        }
        next_file = next_file->next_file;
    }
    uint32 file_name_len = (uint32)strlen(file_name);
    uint32 file_name_size = file_name_len + 1;
    if (cm_alloc_config_buf(config, file_name_size, &ifile->value) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (cm_alloc_config_buf(config, file_name_size, &ifile->pfile_value) != CM_SUCCESS) {
        return CM_ERROR;
    }

    errno_t errcode = strncpy_s(ifile->value, (size_t)file_name_size, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    errcode = strncpy_s(ifile->pfile_value, (size_t)file_name_size, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    ifile->is_diff = CM_FALSE;
    cm_set_config_ifile_inner(config, ifile);
    return cm_parse_config(config, file_buf, buf_len, CM_TRUE, CM_FALSE);
}

static status_t cm_set_config_item_check(const config_item_t *item, const text_t *name, const text_t *value)
{
    if (value->len >= CM_PARAM_BUFFER_SIZE && (item->attr & ATTR_READONLY) == 0) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, T2S(name));
        return CM_ERROR;
    }
    /* HAVE_SSL or _FACTOR_KEY cannot be loaded from config file */
    if (cm_str_equal(item->name, "HAVE_SSL") || cm_str_equal(item->name, "_FACTOR_KEY")) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, T2S(name));
        return CM_ERROR;
    }

    if (cm_str_equal(item->name, "ENABLE_IDX_CONFS_NAME_DUPL") && cm_text_str_equal_ins(value, "TRUE")) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, T2S(name));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cm_set_config_item_value(bool32 ifile_item, config_t *config, text_t *value, text_t *comment,
    config_item_t *item)
{
    uint32 buf_size;
    if (!ifile_item) {
        buf_size = (value->len >= CM_PARAM_BUFFER_SIZE) ? value->len + 1 : CM_PARAM_BUFFER_SIZE;

        /* reuse previous allocated buffer if possible */
        if (buf_size > CM_PARAM_BUFFER_SIZE || item->is_default) {
            CM_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->value));
            CM_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->pfile_value));
            CM_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->runtime_value));
        }

        CM_RETURN_IFERR(cm_text2str(value, item->value, buf_size));
        CM_RETURN_IFERR(cm_text2str(value, item->pfile_value, buf_size));
        CM_RETURN_IFERR(cm_text2str(value, item->runtime_value, buf_size));
        item->is_diff = CM_FALSE;
    }

    if (comment->len > 0) {
        buf_size = comment->len + 1;
        if (cm_alloc_config_buf(config, buf_size, &item->comment) != CM_SUCCESS) {
            return CM_ERROR;
        }
        CM_RETURN_IFERR(cm_text2str(comment, item->comment, buf_size));
    }
    item->is_default = CM_FALSE;
    return CM_SUCCESS;
}

static void cm_set_config_item_infile(bool32 is_infile, config_t *config, config_item_t *item, config_item_t *temp)
{
    if (is_infile) {
        item->flag |= FLAG_INFILE;
        return;
    }
    item->flag = FLAG_ZFILE;

    if (config->first_item == NULL) {
        config->first_item = item;
        config->last_item = item;
    } else if (temp == NULL) {
        config->last_item->next = item;
        config->last_item = item;
    }
}

status_t cm_set_config_item(
    config_t *config, text_t *name, text_t *value, text_t *comment, bool32 is_infile, bool32 set_alias)
{
    bool32 ifile_item = CM_FALSE;
    config_item_t *item = NULL;
    config_item_t *temp = NULL;

    CM_ASSERT(config != NULL);
    CM_ASSERT(value != NULL);
    CM_ASSERT(comment != NULL);

    /* Use IFILE to embed another parameter file within current parameter file */
    if (cm_text_str_equal_ins(name, "IFILE")) {
        if (is_infile) {
            CM_THROW_ERROR(ERR_INVALID_VALUE, T2S(name));
            return CM_ERROR;
        }
        if (cm_set_config_ifile(config, value, &item) != CM_SUCCESS) {
            return CM_ERROR;
        }
        temp = NULL;
        ifile_item = CM_TRUE;
    } else {
        item = cm_get_config_item(config, name, set_alias);
        temp = config->first_item;
        ifile_item = CM_FALSE;
    }

    if (item == NULL) {
        if (!config->ignore) {
            CM_THROW_ERROR(ERR_INVALID_VALUE, T2S(name));
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }

    while (temp != NULL) {
        if (cm_text_str_equal_ins(name, temp->name) ||
            (temp->alias != NULL && cm_text_str_equal_ins(name, temp->alias))) {
            /* check duplicate parameter in main file */
            if (!is_infile && ((temp->flag & FLAG_ZFILE) != 0)) {
                CM_THROW_ERROR(ERR_INVALID_VALUE, temp->name);
                return CM_ERROR;
            }
            break;
        }
        temp = temp->next;
    }

    CM_RETURN_IFERR(cm_set_config_item_check(item, name, value));
    CM_RETURN_IFERR(cm_set_config_item_value(ifile_item, config, value, comment, item));

    cm_set_config_item_infile(is_infile, config, item, temp);
    return CM_SUCCESS;
}

static status_t cm_read_config_file(
    const char *file_name, char *buf, uint32 *buf_len, bool32 is_ifile, bool32 read_only)
{
    int32 file_fd;
    status_t status;
    uint32 mode = (read_only || is_ifile) ? (O_RDONLY | O_BINARY) : (O_CREAT | O_RDWR | O_BINARY);

    if (!cm_file_exist(file_name)) {
        CM_THROW_ERROR(ERR_NOT_EXIST_FILE, "config", file_name);
        return CM_ERROR;
    }

    if (cm_open_file(file_name, mode, &file_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int64 size = cm_file_size(file_fd);
    if (size == -1) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return CM_ERROR;
    }

    if (size > (int64)(*buf_len)) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, file_name);
        return CM_ERROR;
    }

    if (cm_seek_file(file_fd, 0, SEEK_SET) != 0) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CM_ERROR;
    }

    status = cm_read_file(file_fd, buf, (int32)size, (int32 *)buf_len);
    cm_close_file(file_fd);
    return status;
}

static status_t cm_parse_config(config_t *config, char *buf, uint32 buf_len, bool32 is_ifile, bool32 set_alias)
{
    text_t text, line, comment, name, value;
    CM_ASSERT(config != NULL);

    text.len = buf_len;
    text.str = buf;

    comment.str = text.str;
    comment.len = 0;
    uint32 line_no = 0;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        line_no++;
        cm_trim_text(&line);
        if (line.len >= CM_MAX_CONFIG_LINE_SIZE) {
            CM_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, line_no);
            return CM_ERROR;
        }

        if (*line.str == '#' || line.len == 0) { /* commentted line */
            continue;
        }

        comment.len = (uint32)(line.str - comment.str);

        cm_split_text(&line, '=', '\0', &name, &value);
        cm_text_upper(&name);  // Case insensitive
        cm_trim_text(&name);
        cm_trim_text(&value);
        cm_trim_text(&comment);

        if (cm_set_config_item(config, &name, &value, &comment, is_ifile, set_alias) != CM_SUCCESS) {
            return CM_ERROR;
        }

        comment.str = text.str;
        comment.len = 0;
    }

    return CM_SUCCESS;
}

void cm_init_config(config_item_t *items, uint32 item_count, config_t *config)
{
    uint32 i, hash_value;
    config_item_t *item = NULL;
    errno_t rc_memzero;

    CM_ASSERT((items != NULL) && (config != NULL));
    rc_memzero = memset_sp(config, sizeof(config_t), 0, sizeof(config_t));
    if (rc_memzero != EOK) {
        return;
    }

    config->items = items;
    config->item_count = item_count;
    config->value_buf_size = CM_ALIGN4(item_count) * SIZE_K(4);
    for (i = 0; i < item_count; i++) {
        item = &config->items[i];
        item->next = NULL;

        /* initialize hash map by name */
        hash_value = cm_hash_bytes((uint8 *)item->name, (uint32)strlen(item->name), CM_CONFIG_HASH_BUCKETS);
        item->hash_next = config->name_map[hash_value];
        config->name_map[hash_value] = item;
        if (item->alias != NULL) {
            hash_value =
                cm_hash_bytes((uint8 *)item->alias, (uint32)strlen(item->alias), CM_CONFIG_ALIAS_HASH_BUCKETS);
            item->hash_next2 = config->alias_map[hash_value];
            config->alias_map[hash_value] = item;
        }
    }
}

status_t cm_load_config(
    config_item_t *items, uint32 item_count, const char *file_name, config_t *config, bool32 set_alias)
{
    CM_ASSERT((items != NULL) && (file_name != NULL) && (config != NULL));
    size_t name_len = (uint32)strlen(file_name);
    errno_t errcode;

    cm_init_config(items, item_count, config);
    errcode = strncpy_s(config->file_name, CM_FILE_NAME_BUFFER_SIZE, file_name, (size_t)name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    config->text_size = (uint32)sizeof(config->file_buf);
    if (cm_read_config_file(file_name, config->file_buf, &config->text_size, CM_FALSE, CM_FALSE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return cm_parse_config(config, config->file_buf, config->text_size, CM_FALSE, set_alias);
}

status_t cm_read_config(const char *file_name, config_t *config)
{
    CM_ASSERT(file_name != NULL && config != NULL);
    size_t name_len = strlen(file_name);

    errno_t errcode = strncpy_s(config->file_name, CM_FILE_NAME_BUFFER_SIZE, file_name, name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    config->text_size = (uint32)sizeof(config->file_buf);
    if (cm_read_config_file(file_name, config->file_buf, &config->text_size, CM_FALSE, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return cm_parse_config(config, config->file_buf, config->text_size, CM_FALSE, CM_FALSE);
}

void cm_free_config_buf(config_t *config)
{
    if (config->value_buf != NULL) {
        CM_FREE_PROT_PTR(config->value_buf);
        config->value_buf = NULL;
    }
}

static status_t cm_open_config_stream(config_t *config, config_stream_t *stream)
{
    char backup_name[CM_FILE_NAME_BUFFER_SIZE] = { '\0' };
    CM_POINTER2(stream, config);

    stream->config = config;
    stream->offset = 0;

    PRTS_RETURN_IFERR(snprintf_s(backup_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_bak",
                                 config->file_name));

    if (cm_copy_file(config->file_name, backup_name, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // write a tempory file avoid risk operating config file when disk full
    PRTS_RETURN_IFERR(snprintf_s(backup_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp",
                                 config->file_name));

    if (cm_open_file(backup_name, O_CREAT | O_RDWR | O_BINARY | O_SYNC | O_TRUNC, &config->file) != CM_SUCCESS) {
        return CM_ERROR;
    }
    (void)cm_chmod_file(S_IRUSR | S_IWUSR, config->file);

    return CM_SUCCESS;
}

static status_t cm_write_config_stream(config_stream_t *stream, const char *str)
{
    uint32 len;
    CM_POINTER2(stream, str);

    if (str == NULL) {
        return CM_SUCCESS;
    }

    len = (uint32)strlen(str);
    if (len == 0) {
        return CM_SUCCESS;
    }

    if (stream->offset + len > CM_MAX_CONFIG_FILE_SIZE) {
        if (cm_write_file(stream->config->file, stream->config->file_buf, (int32)stream->offset) != CM_SUCCESS) {
            return CM_ERROR;
        }

        stream->offset = 0;
    }

    MEMS_RETURN_IFERR(memcpy_sp(stream->config->file_buf + stream->offset,
        (size_t)(CM_MAX_CONFIG_FILE_SIZE - stream->offset), str, (size_t)len));

    stream->offset += len;
    return CM_SUCCESS;
}

static status_t cm_close_config_stream(config_stream_t *stream)
{
    CM_POINTER(stream);

    if (stream->offset > 0) {
        if (cm_write_file(stream->config->file, stream->config->file_buf, (int32)stream->offset) != CM_SUCCESS) {
            return CM_ERROR;
        }

        stream->offset = 0;
    }

    cm_close_file(stream->config->file);

    // a tempory file rename formal config file
    char temp_name[CM_FILE_NAME_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(temp_name,
        CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp", stream->config->file_name));

    return cm_rename_file(temp_name, stream->config->file_name);
}

status_t cm_save_config(config_t *config)
{
    config_stream_t stream;
    CM_POINTER(config);

    if (cm_open_config_stream(config, &stream) != CM_SUCCESS) {
        return CM_ERROR;
    }

    config_item_t *item = config->first_item;

    while (item != NULL) {
        /* skip item loaded from embeded parameter file */
        if ((item->flag & FLAG_INFILE) > 0) {
            item = item->next;
            continue;
        }

        if (!CM_IS_EMPTY_STR(item->comment)) {
            if (cm_write_config_stream(&stream, item->comment) != CM_SUCCESS) {
                return CM_ERROR;
            }
            if (cm_write_config_stream(&stream, "\n") != CM_SUCCESS) {
                return CM_ERROR;
            }
        }

        if (item->hit_alias) {
            if (cm_write_config_stream(&stream, item->alias) != CM_SUCCESS) {
                return CM_ERROR;
            }
        } else {
            if (cm_write_config_stream(&stream, item->name) != CM_SUCCESS) {
                return CM_ERROR;
            }
        }

        if (cm_write_config_stream(&stream, " = ") != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (cm_write_config_stream(&stream, item->pfile_value) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (cm_write_config_stream(&stream, "\n") != CM_SUCCESS) {
            return CM_ERROR;
        }

        item = item->next;
    }

    return cm_close_config_stream(&stream);
}

// fixing IFILE problems, move changing item to the bottom of config each time
static void cm_set_config_first_last_item(config_t *config, config_item_t *item)
{
    config_item_t *prev_item = NULL;

    if (config->last_item == NULL) {
        config->first_item = item;
        config->last_item = item;
        return;
    }

    if (config->first_item == item) {
        config->first_item = item->next;
    } else if (item->next != NULL) {
        prev_item = config->first_item;
        while ((prev_item != NULL) && (prev_item->next != item)) {
            prev_item = prev_item->next;
        }
        if (prev_item != NULL) {
            prev_item->next = item->next;
        }
    }
    item->next = NULL;
    config->last_item->next = item;
    config->last_item = item;
}

static bool32 cm_check_config_same(config_item_t *item, const char *value)
{
    if (item->is_diff) {
        return CM_FALSE;
    }

    char *old_value = item->is_default ? item->default_value : item->value;
    /* config value is not changed */
    return cm_str_equal(old_value, value);
}

static status_t cm_alter_config_item(config_t *config, config_item_t *item, const char *value, config_scope_t scope)
{
    size_t value_len;
    errno_t errcode;

    if (item->is_default) {
        if (cm_alloc_config_buf(config, CM_PARAM_BUFFER_SIZE, &item->value) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if (cm_alloc_config_buf(config, CM_PARAM_BUFFER_SIZE, &item->pfile_value) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    item->is_default = CM_FALSE;

    value_len = (uint32)strlen(value);
    if (scope != CONFIG_SCOPE_DISK) {
        errcode = strncpy_s(item->value, CM_PARAM_BUFFER_SIZE, value, (size_t)value_len);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
    }
    item->flag &= ~FLAG_INFILE;
    if (scope != CONFIG_SCOPE_MEMORY) {
        errcode = strncpy_s(item->pfile_value, CM_PARAM_BUFFER_SIZE, value, (size_t)value_len);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        if (item != config->last_item) {
            cm_set_config_first_last_item(config, item);
        }
        if (cm_save_config(config) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    item->is_diff = (scope != CONFIG_SCOPE_BOTH) ? CM_TRUE : CM_FALSE;
    return CM_SUCCESS;
}

status_t cm_alter_config(config_t *config, const char *name, const char *value, config_scope_t scope, bool32 force)
{
    text_t name_text;
    config_item_t *item = NULL;
    status_t status;

    CM_POINTER3(config, name, value);
    cm_str2text((char *)name, &name_text);
    item = cm_get_config_item(config, &name_text, CM_FALSE);
    if (item == NULL) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, name);
        return CM_ERROR;
    }
    if ((item->attr & ATTR_READONLY) && !force) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, name);
        return CM_ERROR;
    }

    if (cm_check_config_same(item, value)) {
        return CM_SUCCESS;
    }

    cm_spin_lock(&g_config_lock, NULL);

    if (cm_access_file(config->file_name, F_OK | R_OK | W_OK) != CM_SUCCESS) {
        cm_spin_unlock(&g_config_lock);
        CM_THROW_ERROR(ERR_OPEN_FILE, config->file_name, errno);
        return CM_ERROR;
    }

    status = cm_alter_config_item(config, item, value, scope);
    cm_spin_unlock(&g_config_lock);
    return status;
}

#ifdef __cplusplus
}
#endif
