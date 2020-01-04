#ifndef __PGCACHE_SCAN_H
#define __PGCACHE_SCAN_H

#include "include.h"


/******************** global macro **********************/
/* instruction type */
#define		CALLQ	1
#define		JMPQ	2


/********************************************************/

typedef struct {
    struct list_head list;
    uint64_t ino;
    uint32_t pagecount;
    uint32_t icount;
    uint32_t pid;
    char devname[64];
    char comm[TASK_COMM_LEN];
    char *abspath;
} pgcount_node_t;


/******************* global variable *********************/
/* Lookup the address for this symbol. Returns 0 if not found. */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_name_func;


/**
 *    iterate_supers - call function for all active superblocks
 *    @f: function to call
 *    @arg: argument to pass to it
 *    
 *    Scans the superblock list and calls given function, passing it
 *    locked superblock and given argument.
 **/

typedef void (*iterate_supers_addr)(void (*f)(struct super_block *, void *), void *arg);
extern iterate_supers_addr iterate_supers_function;

#endif
