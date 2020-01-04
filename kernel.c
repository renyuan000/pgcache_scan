#include "pgcache_scan.h"

MODULE_AUTHOR("renyuan");
MODULE_DESCRIPTION("XXXXXX");
MODULE_LICENSE("GPL");


/* our kernel parameter  */
unsigned long kallsyms_lookup_name_addr = 0UL;
module_param(kallsyms_lookup_name_addr, ulong, 0644);
MODULE_PARM_DESC(kallsyms_lookup_name_addr, "It is for  Hooking, Because of no EXPROT_SYMBOL(kallsyms_lookup_name)");

/* Lookup the address for this symbol. Returns 0 if not found. */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_name_func;

struct list_head *_super_blocks = NULL;
spinlock_t *_sb_lock = NULL;
spinlock_t *inode_sb_list_lock = NULL;

extern struct task_struct init_task;


LIST_HEAD(ordered_list);

void order_list_add(pgcount_node_t *new) 
{
    pgcount_node_t *node = NULL, *tmp = NULL;

    if (list_empty(&ordered_list)) {
        list_add(&new->list, &ordered_list);
        return;
    }

    list_for_each_entry_safe(node, tmp, &ordered_list, list) {
        if (new->pagecount > node->pagecount) {
            list_add(&new->list, node->list.prev);
            return;
        } 
    }

    list_add_tail(&new->list, &ordered_list);

    return;
}

void order_list_clear(void)
{
    pgcount_node_t *node = NULL, *tmp = NULL;

    list_for_each_entry_safe(node, tmp, &ordered_list, list) {
        list_del(&node->list);
        kfree(node);
    }

    return;
}

#define K (1024)
#define M (1024 * (K))
#define G (1024 * (M))

void print_top_n(int n)
{
    int count = 0;
    uint64_t gb = 0UL, mb = 0UL, kb = 0UL;
    uint64_t bytes = 0UL;
    pgcount_node_t *node = NULL, *tmp = NULL;

    if (list_empty(&ordered_list)) {
        printk("ordered_list is empty !\n");
        return;
    }

    printk("\n"); 
    list_for_each_entry_safe(node, tmp, &ordered_list, list) {
        if (count++ < n) {
            bytes = node->pagecount * PAGE_SIZE;
            gb  = bytes / G;
            mb  = (bytes - (gb * G)) / M;
            kb  = (bytes - (gb * G) - (mb * M)) / K; 
            
            if (gb != 0) {
                printk("pgscan: %4s ino: %8lu icount: %d pagecache: %8lu %3luGB,%3luMB,%3luKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            } else if (mb != 0) {
                printk("pgscan: %4s ino: %8lu icount: %d pagecache: %8lu %3luGB,%3luMB,%3luKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            } else if (kb != 0) {
                printk("pgscan: %4s ino: %8lu icount: %d pagecache: %8lu %3luGB,%3luMb,%3luKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            }
        }
    }
    printk("\n"); 
}

static void scan_inodes_pagecache_one_sb(struct super_block *sb, void *arg)
{
    struct inode *inode = NULL;
    pgcount_node_t *pgc = NULL;
    struct dentry *de   = NULL;
   
    spin_lock(inode_sb_list_lock);
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
        if (pgc == NULL) {
            pgc = kzalloc((sizeof(pgcount_node_t)), GFP_KERNEL);
            if (pgc == NULL) {
                printk("kmalloc failed, nomem");
                goto out;
            }
        }

        spin_lock(&inode->i_lock);
        struct address_space *mapping = inode->i_mapping;
        if (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW) || mapping->nrpages == 0) {
            spin_unlock(&inode->i_lock);
            continue;
        }
	if (sb->s_bdev && sb->s_bdev->bd_part && sb->s_bdev->bd_disk) {
            pgc->ino = inode->i_ino;
            snprintf(pgc->devname, sizeof(pgc->devname), "%s%d",  sb->s_bdev->bd_disk->disk_name, 
                               sb->s_bdev->bd_part->partno);
            pgc->pagecount = mapping->nrpages;
            pgc->icount = atomic_read(&inode->i_count);
        } else {
            //printk("%s ino: %ul\tnrpages: %ul\n", __FUNCTION__, inode->i_ino, mapping->nrpages);
        }
        
        spin_unlock(&inode->i_lock);
/*
        de = d_find_alias(inode);
        if (de) {
            memset(buf, 0, PATH_MAX);
            res = dentry_path_raw(de, buf, (PATH_MAX - 10 - 1));
        printk("res=%d path = %s\n", IS_ERR(res), buf);
            if (!IS_ERR(res) && d_unlinked(de)) {
                memcpy((ptr + strlen(buf)), "//deleted", 10);
                memcpy(pgc->abspath, buf, strlen(buf));
            }
        }
*/
        order_list_add(pgc);
        pgc = NULL;
    } // list_for_each_entry

out:
    spin_unlock(inode_sb_list_lock);

    return;
}
/**
 *	iterate_supers - call function for all active superblocks
 *	@f: function to call
 *	@arg: argument to pass to it
 *
 *	Scans the superblock list and calls given function, passing it
 *	locked superblock and given argument.
 */
typedef void (*iterate_supers_addr)(void (*f)(struct super_block *, void *), void *arg);
static iterate_supers_addr iterate_supers_function;

static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i;

	/* Find the last open fd */
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	i = (i + 1) * BITS_PER_LONG;
	return i;
}

int scan_file_inode(const void *v, struct file *f, unsigned fd)
{
    char *p = NULL;
    struct address_space *mapping = NULL; 
    pgcount_node_t *pgc = NULL;
    struct super_block *sb = NULL;
    const struct task_struct *tsk = v;

    if (f && f->f_inode) {
        //iget(f->f_inode);
        mapping = f->f_inode->i_mapping;
        if (mapping->nrpages == 0)
            return 0;

        pgc = kzalloc((sizeof(pgcount_node_t) + PATH_MAX + 11), GFP_KERNEL);
        if (pgc == NULL) 
            return -ENOMEM;
        pgc->abspath = (char *)(pgc + 1);
        p = d_path(&f->f_path, pgc->abspath, (PATH_MAX + 11));
        pgc->ino = f->f_inode->i_ino;
        pgc->abspath = p;
        if (f->f_inode->i_sb) {
            sb = f->f_inode->i_sb;
            if (sb && sb->s_bdev && sb->s_bdev->bd_disk)
            snprintf(pgc->devname, sizeof(pgc->devname), "%s%d",  sb->s_bdev->bd_disk->disk_name, 
                               sb->s_bdev->bd_part->partno);
        }
        pgc->pagecount = mapping->nrpages;
        pgc->icount = atomic_read(&f->f_inode->i_count);
        if (tsk) {
            pgc->pid = tsk->pid;
            memcpy(pgc->comm, tsk->comm, TASK_COMM_LEN);
        }
#if 0
        printk("path = %s, ino = %lu fd: %u devname: %s com: %s nrpage： %d\n", pgc->abspath, pgc->ino, fd, 
                     pgc->devname, tsk->comm, pgc->pagecount);
#endif
        if (pgc)
            order_list_add(pgc);
        
        //iput(f->f_inode);
    }

    return 0;
}
 
int scan_process_inodes_pagecache(void)
{
    struct task_struct *p = NULL;
    //struct fdtable *fdt = NULL;
    //const struct cred *cred;
    //pid_t ppid, tpid;

    rcu_read_lock();
    for_each_process(p) {
        if ((p == &init_task) || (p == current)) {
            continue;
        }
        //cred = get_task_cred(p);
	task_lock(p);
        if (p->files) {
            iterate_fd(p->files, 1, scan_file_inode, p);
        }
	task_unlock(p);

//	put_cred(cred);
    }
    rcu_read_unlock();

    return 0;
}



/* Lookup the address for this symbol. Returns 0 if not found. */
kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL;

int get_kallsyms_lookup_name_function(void)
{
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kallsyms_lookup_name_addr;
    if (((kallsyms_lookup_name_addr & 0xffffffff00000000UL) != 0xffffffff00000000UL) || (kallsyms_lookup_name_func == NULL))
        return -1;
    return 0;
}

int get_kernel_not_export_function_and_data(void)
{
    if ((_super_blocks = (void *)kallsyms_lookup_name_func("super_blocks")) == NULL) {
    	printk("super_blocks       = 0x%p\n", _super_blocks);
        return -1;
    }
    printk("super_blocks           = 0x%p\n", (void *)_super_blocks);

    if ((_sb_lock = (void *)kallsyms_lookup_name_func("sb_lock")) == NULL) {
    	printk("sb_lock            = 0x%p\n", _sb_lock);
        return -1;
    }
    printk("sb_lock                = 0x%p\n", (void *)_sb_lock);

    if ((inode_sb_list_lock = (void *)kallsyms_lookup_name_func("inode_sb_list_lock")) == NULL) {
    	printk("inode_sb_list_lock = 0x%p\n", inode_sb_list_lock);
        return -1;
    }
    printk("inode_sb_list_lock     = 0x%p\n", (void *)inode_sb_list_lock);

    if ((iterate_supers_function = (iterate_supers_addr) kallsyms_lookup_name_func("iterate_supers")) == NULL) {
        printk("iterate_supers     = 0x%p\n", iterate_supers_function);
        return -1;
    }
    printk("iterate_supers         = 0x%p\n", iterate_supers_function);

    return 0;
}
//========================================================================================
/* kernel modules init(entry) function */
static __init int init(void)
{
    if (get_kallsyms_lookup_name_function() != 0)
        return -1;
    printk("kallsyms_lookup_name      = 0x%p\n", (void *)kallsyms_lookup_name_addr);
    printk("kallsyms_lookup_name_func = 0x%p\n", (void *)kallsyms_lookup_name_func);

    if (get_kernel_not_export_function_and_data() != 0) 
        return -1;

    //iterate_supers_function(scan_inodes_pagecache_one_sb, NULL);
    scan_process_inodes_pagecache();
    print_top_n(100);
    //tcpspeed_sysctl_register();
    printk("Pgcache scan say: hello !!!\n");
    return 0;
}


/* kernle modules exit function */
static __exit void fini(void)
{
    //tcpspeed_sysctl_unregister();
    order_list_clear();
    printk("Pgcache say: goodbye !!!\n");
    return;
}

module_init(init);
module_exit(fini);
