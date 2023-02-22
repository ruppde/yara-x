#ifndef YARA_X
#define YARA_X

/* Generated with cbindgen:0.24.3 */

/* This file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum YRX_ERROR {
  SUCCESS,
  FOO,
} YRX_ERROR;

typedef struct YRX_RULES YRX_RULES;

/**
 * Compile YARA source code and return the rules in compiled form.
 *
 * The caller is responsible for destroying the YR_RULES object by calling
 * [`yrx_rules_destroy`].
 */
enum YRX_ERROR yrx_compile(const char *src, struct YRX_RULES **rules);

/**
 * Destroys a [`YRX_RULES`] object.
 */
void yrx_rules_destroy(struct YRX_RULES *rules);

#endif /* YARA_X */
