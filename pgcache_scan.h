#ifndef __SPEED_H
#define __SPEED_H
#include "include.h"
#include "extern.h"


/******************** global macro **********************/
/* instruction type */
#define		CALLQ	1
#define		JMPQ	2


/********************************************************/

/******************* global variable *********************/
/* Lookup the address for this symbol. Returns 0 if not found. */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_name_func;


typedef struct {
    struct list_head list;
    uint64_t ino;
    uint32_t pagecount;
    uint32_t icount;
    char devname[64];
    char abspath[0];
} pgcount_node_t;

#endif
