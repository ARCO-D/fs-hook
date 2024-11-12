#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>



void disable_write_protection(unsigned long addr) {
    int ret = 0;

    // cat /proc/kallsyms |grep init_mm
    struct mm_struct* init_mm = (struct mm_struct*)0xffff80008153cdc0;
    
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;

    pgdp = pgd_offset(init_mm, addr);
	if (pgd_none(READ_ONCE(*pgdp))) {
		printk(KERN_INFO "failed pgdp");
	}
	
	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(READ_ONCE(*p4dp))) {
		printk(KERN_INFO "failed p4dp");
	}

	pudp = pud_offset(p4dp, addr);
	if (pud_none(READ_ONCE(*pudp))) {
		printk(KERN_INFO "failed pudp");
	}
	
	pmdp = pmd_offset(pudp, addr);
	if (pmd_none(READ_ONCE(*pmdp))) {
		printk(KERN_INFO "failed pmdp");
	}
	
	ptep = pte_offset_kernel(pmdp, addr);
	if (!pte_valid(READ_ONCE(*ptep))) {
		printk(KERN_INFO "failed pte");
	}
    
    pte_t pte = READ_ONCE(*ptep);

    pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));

    // set_pte_at(init_mm, addr, ptep, pte);
    set_pte(ptep, pte);
    printk("hook_test: set pte over\n");

    // flush_tlb_all();
    __flush_tlb_kernel_pgtable(addr);

    // ret暂未使用
    if (ret) {
        pr_err("hook_test: Failed to change memory protection\n");
    }
    printk("hook_test: disable write protect over\n");
}

void enable_write_protection(unsigned long addr) {
    int ret = 0;
    
    if (ret) {
        pr_err("hook_test: Failed to change memory protection\n");
    }
}

typedef int (*iterate_shared) (struct file *, struct dir_context *);
iterate_shared origin_iterate_shared;

int replace_iterate_shared(struct file *file, struct dir_context *ctx)
{
    printk("hook_test: do hook iterate!\n");
    return 0;
}


int hook_test(void)
{
    printk("hook_test: do hook test\n");
	struct file *file = filp_open("/home", O_RDONLY, 0);
    printk("hook_test: file name:%s\n", file->f_path.dentry->d_name.name);
    printk("hook_test: file->f_op addr 0x%lx\n", (unsigned long)file->f_op);

    // struct file_operations *f_op = kmalloc(sizeof(struct file_operations*), GFP_KERNEL);
    // printk("hook_test: replace f_op addr 0x%p\n", f_op);
    // *f_op = *file->f_op;
    
    origin_iterate_shared = file->f_op->iterate_shared;
    disable_write_protection((unsigned long)file->f_op);
    
    ((struct file_operations*)file->f_op)->iterate_shared = replace_iterate_shared;
    // enable_write_protection((unsigned long)file);

    return 0;
}


static int __init init_hook_test(void)
{
    int ret = 0;
    printk("hook_test: init\n"); 
    hook_test();
    return ret;
}

static void __exit exit_hook_test(void)
{
    printk("hook_test: exit\n");

    struct file *file = filp_open("/home", O_RDONLY, 0);
    
    disable_write_protection((unsigned long)file->f_op);
    
    ((struct file_operations*)file->f_op)->iterate_shared = origin_iterate_shared;

    printk("hook_test: exit\n");
}


MODULE_AUTHOR("ARCO");
MODULE_DESCRIPTION("hook test");
MODULE_LICENSE("GPL");
module_init(init_hook_test);
module_exit(exit_hook_test);
