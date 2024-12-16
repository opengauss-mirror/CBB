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
 * ddes_json.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_json/ddes_json.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddes_json.h"

#define LEXER(json) (&(json)->lexer)
// using for bool, num, string
#define JSON_OFFSET_KEY(jval) (((json_val_t *)(jval))->data)
#define JSON_OFFSET_VAL(jval) (JSON_OFFSET_KEY(jval) + sizeof(key_len_t) + *(key_len_t *)JSON_OFFSET_KEY(jval))
// using for array item
#define JSON_OFFSET_DATA(jval) (((json_val_t *)(jval))->data)

#define LEFT_CURLY_BRACKETS '{'
#define LEFT_SQUARE_BRACKETS '['
#define ALL_DOUBLE_QUOTATION "\"\""

static cm_allocator_t g_json_allocator = { NULL };

typedef struct {
    unsigned char *buf;
    uint32 len;
    uint32 offset;
} str_buf;

void json_register_allocator_func(f_malloc_t register_alloc, f_free_t register_free, void *ctx)
{
    if (g_json_allocator.f_alloc == NULL) {
        g_json_allocator.f_alloc = register_alloc;
    }
    if (g_json_allocator.f_free == NULL) {
        g_json_allocator.f_free = register_free;
    }
    if (g_json_allocator.mem_ctx == NULL) {
        g_json_allocator.mem_ctx = ctx;
    }
}

void json_unregister_allocator_func()
{
    g_json_allocator.f_alloc = NULL;
    g_json_allocator.f_free = NULL;
    g_json_allocator.mem_ctx = NULL;
}

cm_allocator_t *json_get_alloc_func(void)
{
    return &g_json_allocator;
}

status_t jtxt_iter_init(jtxt_iter_t *jtxt, const text_t *txt);
status_t jtxt_iter_obj(bool32 *eof, jtxt_iter_t *json, jtxt_prop_t *prop);
status_t jtxt_iter_arr(bool32 *eof, jtxt_iter_t *jtxt, jtxt_val_t *jval);

/* This function just for test convenience */
status_t jtxt_traverse(jtxt_iter_t *json, uint32 step);

status_t jtxt_iter_init(jtxt_iter_t *jtxt, const text_t *txt)
{
    lang_text_t lang_txt;
    lang_txt.txt = *txt;
    lang_txt.loc.line = 0;
    lang_txt.loc.column = 0;
    lex_init(LEXER(jtxt), &lang_txt);
    word_t word;
    bool32 found = CM_FALSE;
    CM_RETURN_IFERR(lex_try_fetch_cbrackets(LEXER(jtxt), &word, &found));
    if (found) {
        lex_init(LEXER(jtxt), &word.text);
        return CM_SUCCESS;
    }
    CM_RETURN_IFERR(lex_try_fetch_sbrackets(LEXER(jtxt), &word, &found));
    if (found) {
        lex_init(LEXER(jtxt), &word.text);
        return CM_SUCCESS;
    }
    LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "curly or square bracket expected.");
    return CM_ERROR;
}

static status_t fetch_key(jtxt_iter_t *jtxt, jtxt_prop_t *prop)
{
    word_t word;
    bool32 found;
    lex_t *lex = LEXER(jtxt);
    CM_RETURN_IFERR(lex_try_fetch_dquota(lex, &word, &found));
    if (!found) {
        LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "double qutation expected.");
        return CM_ERROR;
    }
    prop->key = word.text.txt;
    return CM_SUCCESS;
}

static status_t fetch_value(jtxt_iter_t *jtxt, jtxt_val_t *jval)
{
    word_t word;
    lex_t *lex = LEXER(jtxt);
    status_t ret;

    lex->flags = LEX_C_STRING;
    CM_RETURN_IFERR(lex_fetch(lex, &word));
    switch (word.type) {
        case WORD_TYPE_BRACKET:
            if (word.text.str[0] == LBRACKET(CURLY_BRACKETS)) {
                jval->type = JSON_OBJ;
            } else {
                jval->type = JSON_ARRAY;
            }
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_NUMBER:
            jval->type = JSON_NUM;
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_DQ_STRING:
            jval->type = JSON_STR;
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_RESERVED:
            if (word.id == RES_WORD_TRUE || word.id == RES_WORD_FALSE) {
                jval->type = JSON_BOOL;
                ret = CM_SUCCESS;
                break;
            }
            ret = CM_ERROR;
            break;
        default:
            LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "invalid value");
            ret = CM_ERROR;
            break;
    }
    jval->val = word.text.txt;
    return ret;
}

static inline status_t skip_comma(jtxt_iter_t *jtxt)
{
    lex_t *lex = LEXER(jtxt);
    word_t word;
    CM_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_SPEC_CHAR && word.type != WORD_TYPE_EOF) {
        LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "comma expected.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t jtxt_iter_obj(bool32 *eof, jtxt_iter_t *json, jtxt_prop_t *prop)
{
    lex_t *lex = LEXER(json);
    bool32 found;

    lex_begin_fetch(lex, NULL);

    if (LEX_CURR == LEX_END) {
        *eof = CM_TRUE;
        return CM_SUCCESS;
    }

    *eof = CM_FALSE;
    CM_RETURN_IFERR(fetch_key(json, prop));
    CM_RETURN_IFERR(lex_try_fetch(lex, ":", &found));
    if (!found) {
        LEX_THROW_ERROR(LEXER(json)->loc, ERR_LEX_SYNTAX_ERROR, "colon expected.");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(fetch_value(json, &prop->val));
    return skip_comma(json);
}

status_t jtxt_iter_arr(bool32 *eof, jtxt_iter_t *jtxt, jtxt_val_t *jval)
{
    lex_t *lex = &jtxt->lexer;

    if (LEX_CURR == LEX_END) {
        *eof = CM_TRUE;
        return CM_SUCCESS;
    }

    *eof = CM_FALSE;
    CM_RETURN_IFERR(fetch_value(jtxt, jval));
    return skip_comma(jtxt);
}

static inline void key2text(void *key, text_t *txt)
{
    txt->str = (char *)key + sizeof(key_len_t);
    txt->len = (uint32)(*(key_len_t *)key - 1);
}

static bool32 json_equal(void *lkey, void *rkey)
{
    text_t ltxt, rtxt;
    key2text(lkey, &ltxt);
    key2text(rkey, &rtxt);
    return (cm_compare_text_ins(&ltxt, &rtxt) == 0);
}

static uint32 json_hash(void *key)
{
    if (key == NULL) {
        return 0;
    }
    text_t txt;
    key2text(key, &txt);
    return cm_hash_bytes((uint8 *)txt.str, txt.len, 0);
}

static bool32 json_equal2(void *lkey, void *rkey)
{
    text_t ltxt, *rtxt;
    key2text(lkey, &ltxt);
    rtxt = (text_t *)rkey;
    return (cm_compare_text_ins(&ltxt, rtxt) == 0);
}

static uint32 json_hash2(void *key)
{
    text_t *txt = (text_t *)key;
    return cm_hash_bytes((uint8 *)txt->str, txt->len, 0);
}

static void *json_key(hash_node_t *node)
{
    return JSON_OFFSET_KEY(node);
}

static hash_funcs_t g_json_hfs = {
    .f_key = json_key,
    .f_equal = json_equal,
    .f_hash = json_hash
};

static hash_funcs_t g_json_hfs2 = {
    .f_key = json_key,
    .f_equal = json_equal2,
    .f_hash = json_hash2
};

static inline uint32 add_val_size(uint32 size, const jtxt_val_t *jtxt_val)
{
    switch (jtxt_val->type) {
        case JSON_BOOL:
            return size + sizeof(bool32);
        case JSON_NUM:
            return size + sizeof(digitext_t);
        case JSON_STR:
            return size + sizeof(jstr_len_t) + jtxt_val->val.len + 1; // include terminator
        case JSON_OBJ:
            return size + sizeof(json_t);
        case JSON_ARRAY:
            return size + sizeof(json_arr_t);
        default:
            return size;
    }
}

static inline uint32 calc_prop_size(jtxt_prop_t *jtxt_prop)
{
    jtxt_val_t *jtxt_val = &jtxt_prop->val;

    /* json value struct|key size|key|val(include terminator)|data */
    uint32 size = sizeof(json_val_t) + sizeof(uint16) + jtxt_prop->key.len + 1;
    return add_val_size(size, jtxt_val);
}

#define TRUE_OR_FALSE(str) (((str)[0] == 't' || (str)[0] == 'T') ? 1 : 0)

static inline void assign_val_data(jtxt_val_t *jtxt_val, char *data)
{
    text_t *txt = &jtxt_val->val;
    switch (jtxt_val->type) {
        case JSON_BOOL:
            *(bool32 *)data = TRUE_OR_FALSE(txt->str);
            break;
        case JSON_NUM:
            cm_text2digitext(txt, (digitext_t *)data);
            break;
        case JSON_STR:
            *(uint32 *)data = txt->len;
            errno_t errcode = memcpy_s(data + sizeof(jstr_len_t), txt->len, txt->str, txt->len);
            securec_check_panic(errcode);
            data[txt->len + sizeof(jstr_len_t)] = '\0';
            break;
        case JSON_OBJ:
        case JSON_ARRAY:
        default:
            // currently do nothing
            break;
    }
}

static void assign_prop_data(jtxt_prop_t *jtxt_prop, json_val_t *jval)
{
    jtxt_val_t *jtxt_val = &jtxt_prop->val;
    char *data = jval->data;
    /* assign key */
    *(uint16 *)data = (uint16)jtxt_prop->key.len + 1;
    data += sizeof(uint16);
    errno_t errcode = memcpy_s(data, jtxt_prop->key.len, jtxt_prop->key.str, jtxt_prop->key.len);
    securec_check_panic(errcode);
    data[jtxt_prop->key.len] = '\0';
    data += jtxt_prop->key.len + 1;

    /* assign val */
    jval->type = jtxt_val->type;
    assign_val_data(jtxt_val, data);
}

static status_t construct_obj(json_t *json, const text_t *txt);
static status_t construct_arr(json_t *json, json_arr_t *arr, const text_t *txt);
static status_t new_obj_prop(json_t *json, jtxt_prop_t *jtxt_prop, json_val_t **jval)
{
    uint32 size = calc_prop_size(jtxt_prop);
    CM_RETURN_IFERR(json->allocator.f_alloc(json->allocator.mem_ctx, size, (void **)jval));
    MEMS_RETURN_IFERR(memset_sp(*jval, size, 0, size));
    assign_prop_data(jtxt_prop, *jval);

    jtxt_val_t *jtxt_val = &jtxt_prop->val;
    switch (jtxt_val->type) {
        case JSON_OBJ:
            ((json_t *)JSON_OFFSET_VAL(*jval))->allocator = json->allocator;
            if (construct_obj((json_t *)JSON_OFFSET_VAL(*jval), &jtxt_val->val) != CM_SUCCESS) {
                json->allocator.f_free(json->allocator.mem_ctx, *jval);
                *jval = NULL;
                return CM_ERROR;
            }
            return CM_SUCCESS;
        case JSON_ARRAY:
            if (construct_arr(json, (json_arr_t *)JSON_OFFSET_VAL(*jval), &jtxt_val->val) != CM_SUCCESS) {
                json->allocator.f_free(json->allocator.mem_ctx, *jval);
                *jval = NULL;
                return CM_ERROR;
            }
            return CM_SUCCESS;
        default:
            return CM_SUCCESS;
    }
}

static status_t construct_obj(json_t *json, const text_t *txt)
{
    jtxt_iter_t jtxt;
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));

    json_val_t *last = json->head;
    uint32 count = 0;
    for (;;) {
        bool32 eof;
        jtxt_prop_t jtxt_prop;
        json_val_t *jval;
        CM_RETURN_IFERR(jtxt_iter_obj(&eof, &jtxt, &jtxt_prop));
        if (SECUREC_UNLIKELY(eof)) {
            break;
        }
        CM_RETURN_IFERR(new_obj_prop(json, &jtxt_prop, &jval));
        ++count;
        if (last == NULL) {
            json->head = jval;
            last = jval;
        } else {
            last->next = jval;
            last->order = jval;
            last = jval;
        }
    }
    hash_map_t *hmap = &json->props;
    CM_RETURN_IFERR(cm_hmap_init(hmap, &json->allocator, count));

    /* the new created value node will be added to hash map directly
        so deal the next pointer carefully */
    if (json->head != NULL) {
        CM_RETURN_IF_FALSE(cm_hmap_insert(hmap, &g_json_hfs, (hash_node_t *)json->head));
        json_val_t *prev, *next;
        prev = json->head;
        next = prev->order;
        while (next != NULL) {
            if (cm_hmap_insert(hmap, &g_json_hfs, (hash_node_t *)next) != CM_TRUE) {
                prev->order = next->order;
                json->allocator.f_free(json->allocator.mem_ctx, next);
                next = prev->order;
                continue;
            }
            prev = next;
            next = next->order;
        }
    }
    return CM_SUCCESS;
}

static inline uint32 calc_item_size(jtxt_val_t *jtxt_val)
{
    // json value struct|data
    uint32 size = sizeof(json_val_t);
    return add_val_size(size, jtxt_val);
}

static status_t append_item(json_t *json, json_arr_t *arr, jtxt_val_t *jtxt_val, json_val_t **jval)
{
    uint32 size = calc_item_size(jtxt_val);
    CM_RETURN_IFERR(json->allocator.f_alloc(json->allocator.mem_ctx, size, (void **)jval));
    MEMS_RETURN_IFERR(memset_sp(*jval, size, 0, size));
    assign_val_data(jtxt_val, (*jval)->data);
    (*jval)->type = jtxt_val->type;
    json_t *obj;

    switch (jtxt_val->type) {
        case JSON_OBJ:
            obj = (json_t *)JSON_OFFSET_DATA(*jval);
            obj->allocator = json->allocator;
            obj->type = JSON_OBJ;
            obj->head = NULL;
            if (construct_obj(obj, &jtxt_val->val) != CM_SUCCESS) {
                json->allocator.f_free(json->allocator.mem_ctx, *jval);
                *jval = NULL;
                return CM_ERROR;
            }
            return CM_SUCCESS;
        case JSON_ARRAY:
            if (construct_arr(json, (json_arr_t *)JSON_OFFSET_DATA(*jval), &jtxt_val->val) != CM_SUCCESS) {
                json->allocator.f_free(json->allocator.mem_ctx, *jval);
                *jval = NULL;
                return CM_ERROR;
            }
            return CM_SUCCESS;
        case JSON_BOOL:
        case JSON_NUM:
        case JSON_STR:
        default:
            return CM_SUCCESS;
    }
}

static status_t construct_arr(json_t *json, json_arr_t *arr, const text_t *txt)
{
    jtxt_iter_t jtxt;
    arr->vals = NULL;
    arr->num = 0;
    json_val_t *last = arr->vals;
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));

    for (;;) {
        bool32 eof;
        jtxt_val_t jtxt_val;
        json_val_t *jval;
        CM_RETURN_IFERR(jtxt_iter_arr(&eof, &jtxt, &jtxt_val));
        if (SECUREC_UNLIKELY(eof)) {
            break;
        }
        CM_RETURN_IFERR(append_item(json, arr, &jtxt_val, &jval));
        if (last == NULL) {
            arr->vals = jval;
        } else {
            last->next = jval;
            last->order = jval;
        }
        arr->num++;
        last = jval;
    }
    return CM_SUCCESS;
}

status_t json_create(json_t **json, const text_t *txt, cm_allocator_t *allocator)
{
    char *str = txt->str;
    json_val_t *jval;
    if (allocator == NULL) {
        return CM_ERROR;
    }
    status_t ret = allocator->f_alloc((void *)allocator->mem_ctx, sizeof(json_t), (void **)json);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    (*json)->allocator = *allocator;
    if (*str == LEFT_CURLY_BRACKETS) {
        (*json)->type = JSON_OBJ;
        (*json)->head = NULL;
        (*json)->props.bucket_num = 0;
        if (construct_obj(*json, txt) != CM_SUCCESS) {
            json_destroy(*json, NULL, allocator);
            *json = NULL;
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }
    if (*str == LEFT_SQUARE_BRACKETS) {
        ret = allocator->f_alloc((void *)allocator->mem_ctx, sizeof(json_t), (void **)&jval);
        if (ret != CM_SUCCESS) {
            allocator->f_free(allocator->mem_ctx, *json);
            *json = NULL;
            return CM_ERROR;
        }
        (*json)->head = jval;
        (*json)->type = JSON_ARRAY;
        jval->type = JSON_ARRAY;
        jval->order = NULL;
        jval->next = NULL;
        if (construct_arr(*json, (json_arr_t *)JSON_OFFSET_VAL(jval), txt) != CM_SUCCESS) {
            json_destroy(*json, NULL, allocator);
            *json = NULL;
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }
    allocator->f_free(allocator->mem_ctx, *json);
    *json = NULL;
    return CM_ERROR;
}

status_t json_create_arr(cm_allocator_t *allocator, json_val_t **arr)
{
    if (allocator == NULL) {
        return CM_ERROR;
    }
    uint32 size = (uint32)sizeof(json_t);
    status_t ret = allocator->f_alloc((void *)allocator->mem_ctx, size, (void **)arr);
    MEMS_RETURN_IFERR(memset_sp(*arr, size, 0, size));
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    (*arr)->type = JSON_ARRAY;
    json_arr_t *jarr = (json_arr_t *)JSON_OFFSET_VAL(*arr);
    jarr->vals = NULL;
    jarr->num = 0;
    return CM_SUCCESS;
}

status_t json_create_obj(json_val_t **jval, json_t **obj, cm_allocator_t *allocator)
{
    if (allocator == NULL) {
        return CM_ERROR;
    }
    uint32 size = (uint32)(sizeof(json_val_t) + sizeof(json_t));
    CM_RETURN_IFERR(allocator->f_alloc((void *)allocator->mem_ctx, size, (void **)jval));
    MEMS_RETURN_IFERR(memset_sp(*jval, size, 0, size));
    (**jval).type = JSON_OBJ;
    *obj = (json_t *) JSON_OFFSET_DATA(*jval);
    (*obj)->allocator = *allocator;
    hash_map_t *hmap = &(*obj)->props;
    if (cm_hmap_init(hmap, allocator, 0) != CM_SUCCESS) {
        allocator->f_free(allocator->mem_ctx, *jval);
        *jval = NULL;
        return CM_ERROR;
    }
    (*obj)->type = JSON_OBJ;
    (*obj)->head = NULL;
    return CM_SUCCESS;
}

static status_t print_item_value(json_val_t *item, str_buf *print_buffer, json_type_t parent_type);
static status_t get_str_buf_print_address(str_buf *print_buffer, int32 will_append_to_buf_len,
    unsigned char **print_address);
static status_t print_str(char *input_str, str_buf *print_buffer);
static status_t print_num(char *input_num, str_buf *print_buffer);
static status_t print_arr(json_arr_t *arr, str_buf *print_buffer);
static status_t print_obj(json_t *json, str_buf *print_buffer);
static void update_offset(str_buf *print_buffer);

status_t json_to_str(json_t *json, char *buf, int32 len)
{
    str_buf str = { 0, 0, 0 };

    if (len <= 0 || buf == NULL || json == NULL) {
        return CM_ERROR;
    }

    str.buf = (unsigned char *)buf;
    str.len = (uint32)len;
    str.offset = 0;

    json_val_t *head = json->head;
    switch (json->type) {
        case JSON_ARRAY:
            CM_RETURN_IFERR(print_arr((json_arr_t *)JSON_OFFSET_VAL(head), &str));
            break;
        case JSON_OBJ:
            CM_RETURN_IFERR(print_obj(json, &str));
            break;
        default:
            return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void update_offset(str_buf *print_buffer)
{
    unsigned char *buffer_pointer = NULL;
    if ((print_buffer == NULL) || (print_buffer->buf == NULL)) {
        return;
    }
    /* offsets the buffer_pointer to the start bit of the last written string. */
    buffer_pointer = print_buffer->buf + print_buffer->offset;
    print_buffer->offset += (uint32)strlen((char *)buffer_pointer);
}


static status_t print_item_value(json_val_t *item, str_buf *print_buffer, json_type_t parent_type)
{
    char *val;
    digitext_t *num;
    json_arr_t *arr;
    json_t *obj;
    if ((item == NULL) || (print_buffer == NULL)) {
        return CM_ERROR;
    }
    switch (item->type) {
        case JSON_NUM:
            num = (digitext_t *)JSON_OFFSET_VAL(item);
            return print_num(num->str, print_buffer);
        case JSON_STR:
            val = JSON_OFFSET_VAL(item) + sizeof(jstr_len_t);
            return print_str(val, print_buffer);
        case JSON_ARRAY:
            arr = (json_arr_t *)JSON_OFFSET_VAL(item);
            return print_arr(arr, print_buffer);
        case JSON_OBJ:
            obj = parent_type == JSON_OBJ ? (json_t *) JSON_OFFSET_VAL(item) : (json_t *) JSON_OFFSET_DATA(item);
            return print_obj(obj, print_buffer);
        default:
            return CM_ERROR;
    }
}

static status_t print_str(char *input_str, str_buf *print_buffer)
{
    unsigned char *print_address = NULL;
    uint32 input_str_len = 0;

    if (print_buffer == NULL) {
        return CM_ERROR;
    }

    /* empty string */
    if (input_str == NULL) {
        CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, sizeof(ALL_DOUBLE_QUOTATION), &print_address));
        if (print_address == NULL) {
            return CM_ERROR;
        }
        MEMS_RETURN_IFERR(strcpy_s((char *)print_address, strlen(ALL_DOUBLE_QUOTATION) + 1, ALL_DOUBLE_QUOTATION));
        return CM_SUCCESS;
    }

    input_str_len = (uint32)strlen(input_str);

    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, (uint32)(input_str_len + sizeof("\"\"")), &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }

    /* print left quotation mark */
    print_address[0] = '\"';
    errno_t errcode = memcpy_s(print_address + 1, print_buffer->len, input_str, input_str_len);
    securec_check_ret(errcode);
    input_str_len++;
    /* print right quotation mark */
    print_address[input_str_len] = '\"';
    input_str_len++;
    /* print string terminator, to update offset in the next step */
    print_address[input_str_len] = '\0';
    return CM_SUCCESS;
}

static status_t print_num(char *input_num, str_buf *print_buffer)
{
    unsigned char *print_address = NULL;
    uint32 num_len = 0;
    if (print_buffer == NULL) {
        return CM_ERROR;
    }

    num_len = (uint32)strlen(input_num);
    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, num_len, &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }
    errno_t errcode = memcpy_s(print_address, print_buffer->len, input_num, num_len);
    securec_check_ret(errcode);
    print_address[num_len] = '\0';
    return CM_SUCCESS;
}

static status_t print_arr(json_arr_t *arr, str_buf *print_buffer)
{
    json_val_t *jvals = arr->vals;
    unsigned char *print_address = NULL;
    uint32 will_append_to_buf_len = 0;

    if (print_buffer == NULL) {
        return CM_ERROR;
    }

    /* [ needs 1 byte */
    will_append_to_buf_len = 1;
    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len, &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }

    *print_address = '[';
    print_buffer->offset++;
    while (jvals != NULL) {
        CM_RETURN_IFERR(print_item_value(jvals, print_buffer, JSON_ARRAY));
        update_offset(print_buffer);
        if (jvals->order) {
            /* , and \0 need 2 bytes */
            will_append_to_buf_len = 1;
            CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len + 1, &print_address));
            if (print_address == NULL) {
                return CM_ERROR;
            }
            *print_address++ = ',';
            *print_address++ = '\0';
            print_buffer->offset += will_append_to_buf_len;
        }
        jvals = jvals->order;
    }

    /* ] and \0 need 2 bytes */
    will_append_to_buf_len = 2;
    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len, &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }
    *print_address++ = ']';
    *print_address = '\0';
    return CM_SUCCESS;
}

static status_t print_obj(json_t *json, str_buf *print_buffer)
{
    unsigned char *print_address = NULL;
    uint32 will_append_to_buf_len = 0;
    json_val_t *jval = json->head;

    if (print_buffer == NULL) {
        return CM_ERROR;
    }

    /* '{' needs 1 byte size. */
    will_append_to_buf_len = 1;
    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len + 1, &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }

    *print_address++ = '{';
    print_buffer->offset += will_append_to_buf_len;

    while (jval) {
        /* print key */
        char *key = JSON_OFFSET_KEY(jval) + sizeof(key_len_t);
        CM_RETURN_IFERR(print_str(key, print_buffer));
        update_offset(print_buffer);

        /* print : */
        will_append_to_buf_len = 1;
        CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len, &print_address));
        if (print_address == NULL) {
            return CM_ERROR;
        }
        *print_address++ = ':';
        print_buffer->offset += will_append_to_buf_len;

        /* print value */
        CM_RETURN_IFERR(print_item_value(jval, print_buffer, JSON_OBJ));
        update_offset(print_buffer);

        /* print , if not last */
        will_append_to_buf_len = 1;
        CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len + 1, &print_address));
        if (print_address == NULL) {
            return CM_ERROR;
        }
        if (jval->order) {
            *print_address++ = ',';
            *print_address = '\0';
            print_buffer->offset += will_append_to_buf_len;
        }
        jval = jval->order;
    }

    CM_RETURN_IFERR(get_str_buf_print_address(print_buffer, will_append_to_buf_len + 1, &print_address));
    if (print_address == NULL) {
        return CM_ERROR;
    }
    *print_address++ = '}';
    *print_address = '\0';
    return CM_SUCCESS;
}

static status_t get_str_buf_print_address(str_buf *print_buffer, int32 will_append_to_buf_len,
    unsigned char **print_address)
{
    if ((print_buffer == NULL) || (print_buffer->buf == NULL)) {
        return CM_ERROR;
    }
    if ((print_buffer->len > 0) && (print_buffer->offset >= print_buffer->len)) {
        return CM_ERROR;
    }
    will_append_to_buf_len += print_buffer->offset + 1;

    if ((uint32)will_append_to_buf_len <= print_buffer->len) {
        *print_address = print_buffer->buf + print_buffer->offset;
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

bool32 json_has_item(json_t *json, text_t *key)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_FALSE;
    }
    hash_map_t *props = &json->props;
    if (props->bucket_num == 0) {
        return CM_FALSE;
    }
    if (cm_hmap_find(&json->props, &g_json_hfs2, key) != NULL) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 json_is_num(json_t *json, text_t *key)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_FALSE;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval != NULL && jval->type == JSON_NUM) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 json_is_str(json_t *json, text_t *key)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_FALSE;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval != NULL && jval->type == JSON_STR) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 json_is_obj(json_t *json, text_t *key)
{
    if (json == NULL) {
        return CM_FALSE;
    }
    if (key == NULL) {
        return json->type == JSON_OBJ ? CM_TRUE : CM_FALSE;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval != NULL && jval->type == JSON_OBJ) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 json_is_arr(json_t *json, text_t *key)
{
    if (json == NULL) {
        return CM_FALSE;
    }
    if (key == NULL) {
        return json->type == JSON_ARRAY ? CM_TRUE : CM_FALSE;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval != NULL && jval->type == JSON_ARRAY) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 json_is_null(json_t *json, text_t *key)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_FALSE;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    char *val = JSON_OFFSET_VAL(jval) + sizeof(jstr_len_t);
    char *compareUpper = "NULL";
    char *compareLower = "null";
    if (strcmp(val, compareUpper) == 0 || strcmp(val, compareLower) == 0) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

status_t json_get_obj(json_t *json, json_t **obj, text_t *key)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_ERROR;
    }
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return CM_ERROR;
    }
    *obj = (json_t *)JSON_OFFSET_VAL(jval);
    return CM_SUCCESS;
}

status_t json_add_str(json_t *json, const char * const key, const char * const val)
{
    if ((json == NULL) || (key == NULL)) {
        return CM_ERROR;
    }

    json_val_t *jval;
    uint32 key_size;
    uint32 val_size;
    uint32 key_len = (uint32)strlen(key);
    uint32 val_len = (uint32)strlen(val);

    key_size = (uint32)(sizeof(json_val_t) + sizeof(uint16) + key_len + 1);
    val_size = (uint32)sizeof(jstr_len_t) + val_len + 1;
    CM_RETURN_IFERR(json->allocator.f_alloc(json->allocator.mem_ctx, key_size + val_size, (void **)&jval));
    char *data = jval->data;
    jval->order = NULL;
    jval->next = NULL;
    *(uint16 *)data = (uint16)key_len + 1;
    data += sizeof(uint16);
    errno_t ret = memcpy_s(data, key_len, key, key_len);
    if (ret != EOK) {
        json->allocator.f_free(json->allocator.mem_ctx, jval);
        return CM_ERROR;
    }
    data[key_len] = '\0';
    data += key_len + 1;

    jval->type = JSON_STR;
    *(uint32 *)data = val_len;
    ret = memcpy_s(data + sizeof(jstr_len_t), val_len, val, val_len);
    if (ret != EOK) {
        json->allocator.f_free(json->allocator.mem_ctx, jval);
        return CM_ERROR;
    }
    data[val_len + sizeof(jstr_len_t)] = '\0';

    hash_map_t hmap = json->props;
    json_val_t *next = json->head;
    if (next == NULL) {
        // duplicate keys cannot be added.
        bool32 res = cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)jval);
        if (res != CM_TRUE) {
            json->allocator.f_free(json->allocator.mem_ctx, jval);
            return CM_ERROR;
        }
        json->head = jval;
        return CM_SUCCESS;
    }
    while (next != NULL) {
        if (next->order == NULL) {
            bool32 res = cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)jval);
            if (res != CM_TRUE) {
                json->allocator.f_free(json->allocator.mem_ctx, jval);
                return CM_ERROR;
            }
            next->next = jval;
            next->order = jval;
            break;
        }
        next = next->order;
    }
    return CM_SUCCESS;
}

status_t json_add_num(json_t *json, const char * const key, const double value)
{
    char val[CM_MAX_NUMBER_LEN];
    int errcode = sprintf_s(val, sizeof(val), "%.0f", value);
    PRTS_RETURN_IFERR(errcode);
    json_val_t *jval;
    uint32 key_size;
    uint32 val_size;
    uint32 key_len = (uint32)strlen(key);
    uint32 val_len = (uint32)strlen(val);

    if (json == NULL) {
        return CM_ERROR;
    }

    key_size = (uint32)(sizeof(json_val_t) + sizeof(uint16) + key_len + 1);
    val_size = (uint32)sizeof(digitext_t);
    CM_RETURN_IFERR(json->allocator.f_alloc(json->allocator.mem_ctx, key_size + val_size, (void **)&jval));
    jval->order = NULL;
    jval->next = NULL;
    char *data = jval->data;
    *(uint16 *)data = (uint16)key_len + 1;
    data += sizeof(uint16);
    errno_t ret = memcpy_s(data, key_len, key, key_len);
    if (ret != EOK) {
        json->allocator.f_free(json->allocator.mem_ctx, jval);
        return CM_ERROR;
    }
    data[key_len] = '\0';
    data += key_len + 1;

    jval->type = JSON_NUM;
    text_t text;
    text.str = val;
    text.len = val_len;
    cm_text2digitext(&text, (digitext_t *)data);

    json_val_t *next = json->head;
    hash_map_t hmap = json->props;
    if (next == NULL) {
        bool32 res = cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)jval);
        if (res != CM_TRUE) {
            json->allocator.f_free(json->allocator.mem_ctx, jval);
            return CM_ERROR;
        }
        json->head = jval;
        return CM_SUCCESS;
    }
    while (next != NULL) {
        if (next->order == NULL) {
            bool32 res = cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)jval);
            if (res != CM_TRUE) {
                json->allocator.f_free(json->allocator.mem_ctx, jval);
                return CM_ERROR;
            }
            next->next = jval;
            next->order = jval;
            break;
        }
        next = next->order;
    }
    return CM_SUCCESS;
}

status_t json_add_arr(json_t *json, const char * const key, json_val_t *arr)
{
    json_arr_t *jarr = (json_arr_t *)JSON_OFFSET_VAL(arr);
    json_val_t *vals = jarr->vals;
    uint32 size = jarr->num;
    uint32 key_len = (uint32)strlen(key);

    char *data = arr->data;
    *(uint16 *)data = (uint16)key_len + 1;
    data += sizeof(uint16);
    errno_t errcode = memcpy_s(data, key_len, key, key_len);
    securec_check_ret(errcode);
    data[key_len] = '\0';

    jarr = (json_arr_t *)JSON_OFFSET_VAL(arr);
    jarr->vals = vals;
    jarr->num = size;

    json_val_t *next = json->head;
    hash_map_t hmap = json->props;
    if (next == NULL) {
        json->head = arr;
        return CM_SUCCESS;
    }
    while (next != NULL) {
        if (next->order == NULL) {
            CM_RETURN_IF_FALSE(cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)arr));
            next->next = arr;
            next->order = arr;
            break;
        }
        next = next->order;
    }
    return CM_SUCCESS;
}

status_t json_add_obj(json_t *json, const char * const key, json_val_t *obj)
{
    json_t *jobj = (json_t *) JSON_OFFSET_DATA(obj);
    cm_allocator_t allocator = jobj->allocator;
    hash_map_t props = jobj->props;
    json_val_t *head = jobj->head;
    json_type_t type = jobj->type;
    uint32 key_len = (uint32)strlen(key);

    char *data = obj->data;
    *(uint16 *)data = (uint16)key_len + 1;
    data += sizeof(uint16);
    errno_t errcode = memcpy_s(data, key_len, key, key_len);
    securec_check_ret(errcode);
    data[key_len] = '\0';

    jobj = (json_t *) JSON_OFFSET_VAL(obj);
    jobj->allocator = allocator;
    jobj->props = props;
    jobj->head = head;
    jobj->type = type;

    json_val_t *next = json->head;
    hash_map_t hmap = json->props;
    if (next == NULL) {
        json->head = obj;
        return CM_SUCCESS;
    }
    while (next != NULL) {
        if (next->order == NULL) {
            CM_RETURN_IF_FALSE(cm_hmap_insert(&hmap, &g_json_hfs, (hash_node_t *)obj));
            next->next = obj;
            next->order = obj;
            break;
        }
        next = next->order;
    }
    return CM_SUCCESS;
}

status_t jarr_add_obj(json_val_t *arr, json_val_t *obj)
{
    json_arr_t *jarr = (json_arr_t *)JSON_OFFSET_VAL(arr);
    json_val_t *vals = jarr->vals;
    if (vals == NULL) {
        jarr->vals = obj;
        return CM_SUCCESS;
    }
    while (vals->order != NULL) {
        vals = vals->order;
    }
    vals->order = obj;
    vals->next = obj;
    jarr->num++;
    return CM_SUCCESS;
}

status_t json_get_str(json_t *json, text_t *key, text_t *txt)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return CM_ERROR;
    }
    char *jval_addr = JSON_OFFSET_VAL(jval);
    txt->str = jval_addr + sizeof(jstr_len_t);
    txt->len = *(jstr_len_t *)jval_addr;
    return CM_SUCCESS;
}

digitext_t *json_get_num(json_t *json, text_t *key)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return NULL;
    }
    return (digitext_t *)JSON_OFFSET_VAL(jval);
}

status_t json_get_uint64(json_t *json, text_t *key, uint64 *val)
{
    digitext_t *num = json_get_num(json, key);
    if (num == NULL) {
        return CM_ERROR;
    }
    return cm_str2uint64(num->str, val);
}

status_t json_get_double(json_t *json, text_t *key, double *value)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return CM_ERROR;
    }
    digitext_t *num = (digitext_t *)JSON_OFFSET_VAL(jval);
    return cm_str2real(num->str, value);
}

status_t json_get_arr(json_t *json, json_arr_t **arr, text_t *key)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return CM_ERROR;
    }
    *arr = (json_arr_t *)JSON_OFFSET_VAL(jval);
    return CM_SUCCESS;
}

status_t jarr_get_size(json_arr_t *jarr, uint32 *size)
{
    *size = jarr->num;
    return CM_SUCCESS;
}

status_t jarr_get_obj(json_arr_t *jarr, json_t **obj, uint32 idx)
{
    json_val_t *jval = jarr->vals;
    for (uint32 i = 0; i < jarr->num; i++) {
        if (i == idx) {
            *obj = (json_t *)JSON_OFFSET_DATA(jval);
            return CM_SUCCESS;
        }
        jval = jval->next;
    }
    return CM_ERROR;
}

static void json_travers_del(json_t *json, cm_allocator_t *allocator);
static void json_del_arr(json_arr_t *jarr, cm_allocator_t *allocator);

void json_destroy(json_t *json, json_val_t *item, cm_allocator_t *allocator)
{
    if ((json != NULL && item != NULL) || allocator == NULL) {
        return;
    }
    if (item != NULL) {
        json_type_t type = item->type;
        json_t *obj = NULL;
        if (type == JSON_ARRAY) {
            json_arr_t *arr = (json_arr_t *)JSON_OFFSET_VAL(item);
            json_del_arr(arr, allocator);
        } else if (type == JSON_OBJ) {
            obj = (json_t *)JSON_OFFSET_DATA(item);
            json_travers_del(obj, allocator);
        }
        allocator->f_free(allocator->mem_ctx, item);
        return;
    }
    if (json != NULL) {
        json_travers_del(json, allocator);
        allocator->f_free(allocator->mem_ctx, json);
    }
}

static void json_travers_del(json_t *json, cm_allocator_t *allocator)
{
    /* props needs to be free. */
    if (json->type == JSON_OBJ && json->props.bucket_num > 0) {
        allocator->f_free(allocator->mem_ctx, json->props.buckets);
    }
    json_val_t *jval;
    jval = json->head;
    if (jval != NULL) {
        json_val_t *prev = jval;
        json_arr_t *arr;
        json_val_t *curr;
        while (prev != NULL) {
            json_type_t type = prev->type;
            if (type == JSON_ARRAY) {
                arr = (json_arr_t *) JSON_OFFSET_VAL(prev);
                json_del_arr(arr, allocator);
            } else if (type == JSON_OBJ) {
                json_t *obj = (json_t *) JSON_OFFSET_VAL(prev);
                json_travers_del(obj, allocator);
            }
            curr = prev;
            prev = prev->order;
            allocator->f_free(allocator->mem_ctx, curr);
        }
    }
}

static void json_del_arr(json_arr_t *jarr, cm_allocator_t *allocator)
{
    json_val_t *jvals = jarr->vals;
    json_val_t *curr = NULL;
    json_t *obj;
    while (jvals != NULL) {
        switch (jvals->type) {
            case JSON_OBJ:
                obj = (json_t *)JSON_OFFSET_DATA(jvals);
                json_travers_del(obj, allocator);
                break;
            case JSON_ARRAY:
            case JSON_STR:
            case JSON_NUM:
            default:
                break;
        }
        curr = jvals;
        jvals = jvals->order;
        allocator->f_free(allocator->mem_ctx, curr);
    }
}

status_t json2arr(json_t *json, json_arr_t **jarr)
{
    if (json->type != JSON_ARRAY) {
        return CM_ERROR;
    }
    *jarr = (json_arr_t *)JSON_OFFSET_VAL(json->head);
    return CM_SUCCESS;
}

status_t arr2json(json_val_t *jarr, json_t **json, cm_allocator_t *allocator)
{
    if (jarr->type != JSON_ARRAY) {
        return CM_ERROR;
    }
    uint32 size = (uint32)(sizeof(json_t) + sizeof(json_val_t));
    CM_RETURN_IFERR(allocator->f_alloc((void *)allocator->mem_ctx, size, (void **)json));
    MEMS_RETURN_IFERR(memset_sp(*json, size, 0, size));
    (*json)->head = jarr;
    (*json)->type = JSON_ARRAY;
    return CM_SUCCESS;
}