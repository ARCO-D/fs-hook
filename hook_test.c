#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/page-flags.h>
#include <asm-generic/cacheflush.h>


// 定义结构体用于传递参数给change_page_range函数
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

// 回调函数，用于修改pte的属性
static int change_page_range(pte_t *ptep, unsigned long addr, void *data) {
    struct page_change_data *cdata = data;
    pte_t pte = READ_ONCE(*ptep);
    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);
    set_pte(ptep, pte);
    return 0;
}

// 用于更改内存页面范围的内存权限
int change_memory_common(unsigned long start, unsigned long size, pgprot_t new_prot) {
    
    unsigned long init_mm = 0xffff80008153cdc0;
    // 使用 kallsyms_lookup_name 查找 sys_call_table 符号的地址
    // init_mm = kallsyms_lookup_name("init_mm");

    struct page_change_data data = {
        .set_mask = pgprot_val(new_prot) & ~pgprot_val(PAGE_KERNEL_RO),
        .clear_mask = _PAGE_READONLY,
    };
    return apply_to_page_range((struct mm_struct *)init_mm, start, size, change_page_range, &data);
}

int (*set_memory_rw)(unsigned long addr, int numpages) = (int (*)(unsigned long , int))0xffff800080036c68;


void disable_write_protection(unsigned long addr) {
    int ret = 0;
    pgprot_t pt;
    pt.pgprot = _PAGE_SHARED;
    printk("hook_test: addr=0x%lx\n", addr);
    // printk("hook_test: addr_start=0x%lx\n", addr - (addr % PAGE_SIZE));
    unsigned long addr_start1 = addr + (PAGE_SIZE - (addr % PAGE_SIZE));
    unsigned long addr_start2 = addr - (addr % PAGE_SIZE);
    printk("hook_test: addr_start1=0x%lx\n", addr_start1);
    printk("hook_test: addr_start2=0x%lx\n", addr_start2);
    printk("hook_test: PAGE_SIZE=0x%lx\n", PAGE_SIZE);

    // change_memory_common(addr - (addr % PAGE_SIZE), PAGE_SIZE, pt);

    set_memory_rw(addr_start1, 2);
    set_memory_rw(addr_start2, 2);
    
    flush_tlb_all();

    if (ret) {
        pr_err("hook_test: Failed to change memory protection\n");
    }
    printk("hook_test: disable write protect\n");
}

void enable_write_protection(unsigned long addr) {
    int ret = 0;
    // change_memory_common(addr, PAGE_SIZE, PAGE_U_R);
    if (ret) {
        pr_err("hook_test: Failed to change memory protection\n");
    }
}

typedef int (*origin_iterate_shared) (struct file *, struct dir_context *);

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
    printk("hook_test: file addr 0x%lx\n", file);
    printk("hook_test: file->f_op addr 0x%lx\n", file->f_op);
    printk("hook_test: file->f_op->iterate_shared addr 0x%lx\n", file->f_op->iterate_shared);

    // struct file_operations *f_op = kmalloc(sizeof(struct file_operations*), GFP_KERNEL);
    // printk("hook_test: replace f_op addr 0x%p\n", f_op);
    // *f_op = *file->f_op;
    
    // origin_iterate_shared = f_op->iterate_shared;
    disable_write_protection((unsigned long)file->f_op);
    disable_write_protection((unsigned long)file->f_op->iterate_shared);
    // file->f_op->iterate_shared = replace_iterate_shared;
    // enable_write_protection((unsigned long)file);

    // file->f_op = f_op;

    // printk("hook_test: replace_iterate_shared addr 0x%p\n", replace_iterate_shared);

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
}


MODULE_AUTHOR("ARCO");
MODULE_DESCRIPTION("hook test");
MODULE_LICENSE("GPL");
module_init(init_hook_test);
module_exit(exit_hook_test);
