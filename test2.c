#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

// cat /proc/kallsyms |grep sys_init_mm

struct mm_struct *sys_init_mm = (struct mm_struct *) 0xffff80008151ce00;

pud_t* get_addr_pudp(unsigned long addr, int* retval)
{
    pgd_t *pgdp = NULL;
    p4d_t *p4dp = NULL;
    pud_t *pudp = NULL;

    pgdp = pgd_offset(sys_init_mm, addr);
    if (pgd_none(READ_ONCE(*pgdp))) {
        printk(KERN_INFO "test2: failed pgdp");
        *retval = 1;
    }

    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(READ_ONCE(*p4dp))) {
        printk(KERN_INFO "test2: failed p4dp");
        *retval = 2;
    }

    pudp = pud_offset(p4dp, addr);
    if (pud_none(READ_ONCE(*pudp))) {
        printk(KERN_INFO "test2: failed pudp");
        *retval = 3;
    }

    *retval = 0;
    return pudp;
}

pmd_t* get_addr_pmdp(unsigned long addr, int* retval)
{
    pud_t *pudp = NULL;
    pmd_t *pmdp = NULL;

    *retval = 0;
    pudp = get_addr_pudp(addr, retval);
    if (*retval) return pmdp;

    pmdp = pmd_offset(pudp, addr);
    if (pmd_none(READ_ONCE(*pmdp))) {
        printk(KERN_INFO "test2: failed pmdp");
        *retval = 4;
    }

    return pmdp;
}

pte_t* get_addr_ptep(unsigned long addr, int* retval)
{
    pmd_t *pmdp = NULL;
    pte_t *ptep = NULL;

    *retval = 0;
    pmdp = get_addr_pmdp(addr, retval);
    if (*retval) return ptep;

    ptep = pte_offset_kernel(pmdp, addr);
    if (!pte_valid(READ_ONCE(*ptep))) {
        printk(KERN_INFO "test2: failed pte");
        *retval = 5;
    }

    return ptep;
}

int check_addr_writable(unsigned long addr)
{
    int ret = 0, rw_situation = 0;
    pte_t *ptep = NULL;
    pmd_t *pmdp = NULL;
    // check if pmdp writable
    pmdp = get_addr_pmdp(addr, &ret);
    if (!(pmd_val(*pmdp) & PTE_WRITE)) {
        printk("test2: %lx hasn't set PMD_WRITE\n", addr);
        rw_situation += 4;
    }
    if (!(pmd_val(*pmdp) & PTE_RDONLY)) {
        printk("test2: %lx has set PMD_RDONLY\n", addr);
        rw_situation += 8;
    }

    // check if ptep writable
    ptep = get_addr_ptep(addr, &ret);
    if (!(ptep->pte & PTE_WRITE)) {
        printk("test2: %lx hasn't set PTE_WRITE\n", addr);
        rw_situation += 1;
    }
    if (ptep->pte & PTE_RDONLY) {
        printk("test2: %lx has set PTE_RDONLY\n", addr);
        rw_situation += 2;
    }
    return rw_situation;
}

int check_pte_writable(pte_t pte)
{
    int ret = 0;
    if (!(pte.pte & PTE_WRITE)) {
        ret += 1;
    }
    if (pte.pte & PTE_RDONLY) {
        ret += 2;
    }
    return ret;
}

int make_addr_writable(unsigned long addr)
{
    int ret;

    pmd_t *pmdp;
    pte_t *ptep;

    pmdp = get_addr_pmdp(addr, &ret);
    ret = check_pte_writable(pmd_pte(*pmdp));
    if (ret) {
//        printk("test2: addr %lx pmd=%lx is rdonly\n", addr, (unsigned long) *pmdp);
        *pmdp = pmd_mkwrite_novma(*pmdp);
//        printk("test2: addr %lx pmd set to %lx\n", addr, (unsigned long) *pmdp);
    }

    ptep = get_addr_ptep(addr, &ret);
    if (ret != 0) {
        printk("test2: make_addr_writable get ptep failed\n");
    }

    pte_t pte = READ_ONCE(*ptep);
    pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
    pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));

    // set_pte_at(sys_init_mm, addr, ptep, pte);
    set_pte(ptep, pte);
    printk("test2: make_addr_writable set pte over\n");

    // flush_tlb_all();
    __flush_tlb_kernel_pgtable(addr);
    return ret;
}


void disable_write_protection(unsigned long addr)
{
    int ret = 0;
    pte_t *ptep, *ptep2, *ptep3;

    ret = check_addr_writable(addr);
    if (ret) printk("test2: %lx isn't writable\n", addr);

    ptep = get_addr_ptep(addr, &ret);
    printk("test2: %lx 's ptep is %lx", addr, (unsigned long) ptep);
//    printk("test2: %lx 's pte  is %lx", addr, (unsigned long) *ptep);
    ret = check_addr_writable((unsigned long) ptep);
    if (!ret) goto mkaddrw; // if ptep is writable, then change pte

    ptep2 = get_addr_ptep((unsigned long) ptep, &ret);
    printk("test2: %lx 's ptep2  is %lx", (unsigned long) ptep, (unsigned long) ptep2);
//    printk("test2: %lx 's pte2   is %lx", (unsigned long) *ptep, (unsigned long) *ptep2);
    ret = check_addr_writable((unsigned long) ptep2);
    if (!ret) goto mkptepw;

    ptep3 = get_addr_ptep((unsigned long) ptep2, &ret);
    printk("test2: %lx 's ptep3  is %lx", (unsigned long) ptep2, (unsigned long) ptep3);
//    printk("test2: %lx 's pte3   is %lx", (unsigned long) *ptep2, (unsigned long) *ptep3);
    ret = check_addr_writable((unsigned long) ptep3);
    if (!ret) goto mkptep2w;


    mkptep2w:
    printk("test2: %lx(ptep2) is not writable\n", (unsigned long) ptep2);
    make_addr_writable((unsigned long) ptep2);

    mkptepw:
    printk("test2: %lx(ptep) is not writable\n", (unsigned long) ptep);
    make_addr_writable((unsigned long) ptep);

    mkaddrw:
    printk("test2: %lx(paddr) is not writable\n", (unsigned long) addr);
    make_addr_writable(addr);

    printk("test2: disable_write_protection over");
}

void enable_write_protection(unsigned long addr) {
    int ret = 0;
    
    if (ret) {
        pr_err("hook_test: Failed to change memory protection\n");
    }
}

typedef int (*arco_vfs_getattr) (const struct path*, struct kstat*, u32, unsigned int);
arco_vfs_getattr origin_vfs_getattr;
int replace_vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    printk("test2: replace_vfs_getattr\n");
    return origin_vfs_getattr(path, stat, request_mask, query_flags);
}

static int test2(void)
{
    unsigned long *vfs_getattr = (unsigned long*) 0xffff8000802cc0cc;

    // vfs_getattr ffff8000802cc0cc
    disable_write_protection((unsigned long) vfs_getattr);

    *vfs_getattr = &replace_vfs_getattr;

    return 0;
}

static int __init init_hook_test(void)
{
    int ret = 0;
    printk("test2: init\n");
    test2();
    printk("test2: init over\n");
    return ret;
}

static void __exit exit_hook_test(void)
{
    printk("test2: exit\n");
}


MODULE_AUTHOR("ARCO");
MODULE_DESCRIPTION("hook test");
MODULE_LICENSE("GPL");
module_init(init_hook_test);
module_exit(exit_hook_test);
