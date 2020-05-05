
int walk_process_pagetable(struct task_struct *tsk) 
{
	int ret = 0;
	unsigned long start_vaddr;
	unsigned long end_vaddr;
	struct mm_walk pagemap_walk = {};
	struct mm_struct *mm = tsk->mm;
	struct pagemapread pm;

	if (!mm || !mmget_not_zero(mm))
		goto out;

	start_vaddr = 0UL;
	end_vaddr = mm->task_size;

	pm.show_pfn = true;
	pm.len = (PAGEMAP_WALK_SIZE >> PAGE_SHIFT);
	pm.buffer = kmalloc_array(pm.len, PM_ENTRY_BYTES, GFP_KERNEL);
	ret = -ENOMEM;
	if (!pm.buffer)
		goto out_mem;

	while (start_vaddr < end_vaddr) {
		unsigned long end;

		if (end > end_vaddr) {
			end = end_vaddr;
		}
	
		down_read(&mm->mmap_sem);
		ret = walk_page_range(start_vaddr, end, &pagemap_walk);
		up_read(&mm->mmap_sem);
		start_vaddr = end;

		
	}


	return ret;
}
