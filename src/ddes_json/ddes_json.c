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
    errno_t err = memcpy_s(data, jtxt_prop->key.len, jtxt_prop->key.str, jtxt_prop->key.len);
    securec_check_panic(err);
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
    CM_RETURN_IFERR(json->alloc.f_alloc(json->alloc.mem_ctx, size, (void**)jval));
    assign_prop_data(jtxt_prop, *jval);

    jtxt_val_t *jtxt_val = &jtxt_prop->val;
    switch (jtxt_val->type) {
        case JSON_OBJ:
            ((json_t *)JSON_OFFSET_VAL(*jval))->alloc = json->alloc;
            return construct_obj((json_t *)JSON_OFFSET_VAL(*jval), &jtxt_val->val);
        case JSON_ARRAY:
            return construct_arr(json, (json_arr_t *)JSON_OFFSET_VAL(*jval), &jtxt_val->val);
        default:
            return CM_SUCCESS;
    }
}

static status_t construct_obj(json_t *json, const text_t *txt)
{
    jtxt_iter_t jtxt;
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));

    json_val_t *first = NULL;
    json_val_t *last = NULL;
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
        jval->next = NULL;
        if (last == NULL) {
            first = jval;
            last = jval;
        } else {
            last->next = jval;
            last = jval;
        }
    }

    hash_map_t *hmap = &json->props;
    CM_RETURN_IFERR(cm_hmap_init(hmap, &json->alloc, count));

    // the new created value node will be added to hash map directly
    // so deal the next pointer carefully
    json_val_t *prev, *next = first;
    while (next != NULL) {
        prev = next;
        next = next->next;
        (void)cm_hmap_insert(hmap, &g_json_hfs, (hash_node_t *)prev);
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
    CM_RETURN_IFERR(json->alloc.f_alloc(json->alloc.mem_ctx, size, (void**)jval));
    assign_val_data(jtxt_val, (*jval)->data);

    (*jval)->next = NULL;
    (*jval)->type = jtxt_val->type;

    switch (jtxt_val->type) {
        case JSON_OBJ:
            ((json_t *)JSON_OFFSET_DATA(*jval))->alloc = json->alloc;
            return construct_obj((json_t *)JSON_OFFSET_DATA(*jval), &jtxt_val->val);

        case JSON_ARRAY:
            return construct_arr(json, (json_arr_t *)JSON_OFFSET_DATA(*jval), &jtxt_val->val);

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
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));
    arr->vals = NULL;
    arr->num = 0;
    json_val_t *last = arr->vals;

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
        }
        arr->num++;
        last = jval;
    }
    return CM_SUCCESS;
}

status_t json_create(json_t **json, const text_t *txt, cm_allocator_t *alloc)
{
    if (alloc == NULL) {
        return CM_ERROR;
    }
    
    status_t ret = alloc->f_alloc((void *)alloc->mem_ctx, sizeof(json_t), (void **)json);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    (*json)->alloc = *alloc;
    return construct_obj(*json, txt);
}

void json_destory(json_t *json)
{
    // do nothing now
}

void json_to_str(json_t *json, char *buf, int32 len)
{
}

bool32 json_has_item(json_t *json, text_t *key)
{
    if (cm_hmap_find(&json->props, &g_json_hfs2, key) != NULL) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

json_t *json_get_obj(json_t *json, text_t *key)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return NULL;
    }
    return (json_t *)JSON_OFFSET_VAL(jval);
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
    txt->len =  *(jstr_len_t *)jval_addr;
    return CM_SUCCESS;
}

status_t json_get_bool(json_t *json, text_t *key, bool32 *val)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return CM_ERROR;
    }
    *val = *(bool32 *)JSON_OFFSET_VAL(jval);
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

json_arr_t *json_get_arr(json_t *json, text_t *key)
{
    json_val_t *jval;
    jval = (json_val_t *)cm_hmap_find(&json->props, &g_json_hfs2, key);
    if (jval == NULL) {
        return NULL;
    }
    return (json_arr_t *)JSON_OFFSET_VAL(jval);
}

uint32 jarr_get_size(json_arr_t *jarr)
{
    return jarr->num;
}

json_t *jarr_get_obj(json_arr_t *jarr, uint32 idx)
{
    json_val_t *jval = jarr->vals;
    for (uint32 i = 0; i < jarr->num; i++) {
        if (i == idx) {
            return (json_t *)JSON_OFFSET_DATA(jval);
        }
        jval = jval->next;
    }
    return NULL;
}

