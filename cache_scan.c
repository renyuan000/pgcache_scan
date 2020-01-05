/*
 * written by renyuan on 2020.1.4
 *
 *
 */
#include "include.h"
#include "extern.h"
#include "pgcache_scan.h"


struct list_head *_super_blocks = NULL;
spinlock_t *_sb_lock = NULL;
spinlock_t *inode_sb_list_lock = NULL;

extern struct task_struct init_task;
iterate_supers_addr iterate_supers_function;



LIST_HEAD(ordered_list);


void order_list_clear(void);
void print_top_n(int n);
void scan_inodes_pagecache_one_sb(struct super_block *sb, void *arg);
int scan_file_inode(const void *v, struct file *f, unsigned fd);
int scan_caches_sysctl_handler(struct ctl_table *table, int write,
        void __user *buffer, size_t *length, loff_t *ppos);




static void order_list_add(pgcount_node_t *new) 
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
                printk("pgscan: %4s ino: %8llu icount: %u pagecache: %8llu %3lluGB,%3lluMB,%3lluKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            } else if (mb != 0) {
                printk("pgscan: %4s ino: %8llu icount: %u pagecache: %8llu %3lluGB,%3lluMB,%3lluKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            } else if (kb != 0) {
                printk("pgscan: %4s ino: %8llu icount: %u pagecache: %8llu %3lluGB,%3lluMb,%3lluKB pid: %-6u comm: %s path: %s\n", 
                    node->devname, node->ino, node->icount, node->pagecount, gb, mb, kb, node->pid, node->comm, node->abspath);
            }
        }
    }
    printk("\n"); 
}

void scan_inodes_pagecache_one_sb(struct super_block *sb, void *arg)
{
    struct inode *inode = NULL;
    pgcount_node_t *pgc = NULL;
    struct address_space *mapping = NULL;
    //struct dentry *de   = NULL;
   
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
        mapping = inode->i_mapping;
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

#if 0
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
#endif

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

        if (sysctl_pgcache_scan_file_deleted_but_used) {
            if (!((f->f_inode->i_nlink == 0) && (atomic_read(&f->f_inode->i_count) != 0))) {
                return 0;
            }
        }
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

int scan_caches_sysctl_handler(struct ctl_table *table, int write,
        void __user *buffer, size_t *length, loff_t *ppos)
{
    int ret = 0;

    ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
    if (ret)
        return ret;
#if 0
    printk("%s ret = %d sysctl_pgcache_scan_mode = %d\n", __FUNCTION__, ret, sysctl_pgcache_scan_mode);
#endif
    if (write) {
        switch (sysctl_pgcache_scan_mode) {
            case 0:
                order_list_clear();
                scan_process_inodes_pagecache();
                print_top_n(sysctl_pgcache_scan_top_n);
                break;
            case 1:
                order_list_clear();
                iterate_supers_function(scan_inodes_pagecache_one_sb, NULL);
                print_top_n(sysctl_pgcache_scan_top_n);
                break;
            case 2:
                order_list_clear();
                iterate_supers_function(scan_inodes_pagecache_one_sb, NULL);
                scan_process_inodes_pagecache();
                print_top_n(sysctl_pgcache_scan_top_n);
                break;
            default:
                break;
        }
    }

    return 0;
}


