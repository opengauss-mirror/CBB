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
 * ddes_json.h
 *
 *
 * IDENTIFICATION
 *    src/ddes_json/ddes_json.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_JSON_H__
#define __DDES_JSON_H__


#include "cm_text.h"
#include "cm_hash.h"
#include "cm_error.h"
#include "ddes_lexer.h"
#include "cm_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_json_type {
    JSON_BOOL,
    JSON_NUM,
    JSON_STR,
    JSON_OBJ,
    JSON_ARRAY,
} json_type_t;

typedef struct st_jtxt_val {
    json_type_t type;
    text_t val;
} jtxt_val_t;

typedef struct st_jtxt_prop {
    text_t key;
    jtxt_val_t val;
} jtxt_prop_t;

typedef struct st_json_iter {
    lex_t lexer;
} jtxt_iter_t;

typedef struct st_json_val {
    struct st_json_val *next;
    struct st_json_val *order;
    json_type_t type;
    char data[];
} json_val_t;

typedef struct st_json_arr {
    json_val_t *vals;
    uint32 num;
} json_arr_t;

typedef struct st_json_t {
    cm_allocator_t allocator;
    hash_map_t props;
    struct st_json_val *head;
    json_type_t type;
} json_t;

typedef uint32 jstr_len_t;
typedef uint16 key_len_t;

status_t json_create(json_t **json, const text_t *txt, cm_allocator_t *allocator);

/*
 * Description: if you want to add an array to json, use this function to create an empty json array.
 * Parameter: allocator - memory application function
 *            arr - a newly created empty json array
 */
status_t json_create_arr(cm_allocator_t *allocator, json_val_t **arr);

/*
 * Description: if you want to nest object in json, use this function to create an empty json object.
 * Parameter: jval - if you want to nest the created object into another element later, use jval.
 *            obj - if you want to add new elements to the created object later, use json.
 *            allocator - memory application function
 */
status_t json_create_obj(json_val_t **jval, json_t **obj, cm_allocator_t *allocator);
/*
 * Description: free the JSON memory.
 * Parameter: json - if you use json_create to obtain json, use the first argument.
 *            item - if you use json_create_arr or json_create_obj to obtain jval, use the second argument.
 *            allocator - memory application function
 */
void json_destroy(json_t *json, json_val_t *item, cm_allocator_t *allocator);
status_t json_to_str(json_t *json, char *buf, int32 len);

bool32 json_has_item(json_t *json, text_t *key);

status_t json_get_obj(json_t *json, json_t **obj, text_t *key);
status_t json_get_str(json_t *json, text_t *key, text_t *txt);
digitext_t *json_get_num(json_t *json, text_t *key);
status_t json_get_double(json_t *json, text_t *key, double *value);
status_t json_get_uint64(json_t *json, text_t *key, uint64 *val);
status_t json_get_arr(json_t *json, json_arr_t **arr, text_t *key);
status_t jarr_get_size(json_arr_t *jarr, uint32 *size);
status_t jarr_get_obj(json_arr_t *jarr, json_t **obj, uint32 idx);

status_t json_add_str(json_t *json, const char * const key, const char * const val);
status_t json_add_num(json_t *json, const char * const key, const double value);

/* add object to array */
status_t jarr_add_obj(json_val_t *arr, json_val_t *obj);

/* add array to object */
status_t json_add_arr(json_t *json, const char * const key, json_val_t *arr);

/* add object to object */
status_t json_add_obj(json_t *json, const char * const key, json_val_t *obj);

bool32 json_is_num(json_t *json, text_t *key);
bool32 json_is_str(json_t *json, text_t *key);
bool32 json_is_obj(json_t *json, text_t *key);
bool32 json_is_arr(json_t *json, text_t *key);
bool32 json_is_null(json_t *json, text_t *key);

status_t json2arr(json_t *json, json_arr_t **jarr);
status_t arr2json(json_val_t *jarr, json_t **json, cm_allocator_t *allocator);

void json_register_allocator_func(f_malloc_t register_alloc, f_free_t register_free, void *ctx);
cm_allocator_t *json_get_alloc_func(void);

#ifdef __cplusplus
}
#endif

#endif