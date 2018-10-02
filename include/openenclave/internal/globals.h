// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_GLOBALS_H
#define _OE_GLOBALS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

/* Enclave */
const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

/* Reloc */
const void* __oe_get_reloc_base(void);
const void* __oe_get_reloc_end(void);
const size_t __oe_get_reloc_size(void);

/* ECall */
const void* __oe_get_ecall_base(void);
const void* __oe_get_ecall_end(void);
const size_t __oe_get_ecall_size(void);

/* Heap */
const void* __oe_get_heap_base(void);
const void* __oe_get_heap_end(void);
const size_t __oe_get_heap_size(void);

/* The enclave handle passed by host during initialization */
extern oe_enclave_t* oe_enclave;

OE_EXTERNC_END

#endif /* _OE_GLOBALS_H */
