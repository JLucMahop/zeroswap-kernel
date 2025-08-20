#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "dbs_pmap.h"
#include <linux/version.h>
#include <linux/kdev_t.h>
#include <linux/device/class.h> 
#include <linux/gfp.h>
#include <linux/delay.h>
/* zeroswap */
#define DEVICE_NAME "dbs_va2sec"
#define CLASS_NAME  "dbs_wdev_class"

// -------------------- Device Interface --------------------

static int major;
static struct class *wdbs_class = NULL;
static struct device *wdbs_device = NULL;
static dev_t first;
static struct cdev c_dev;

pages_va_map_t *p2va_map;

pages_va_map_t *va2sec_map;

static int wdevice_open(struct inode *inode, struct file *file) {   
    pr_info("@v --> sector Hashmap device opened\n");
    return 0;
}

static int wdevice_release(struct inode *inode, struct file *file) {
    if (!va2sec_map || !va2sec_map->pages) {
        pr_err("Virt Addr to Sector memory not allocated\n");
        return -ENOMEM;
    }
    //va2sec_map_clear_all();

    return 0;
}


/*static int wdevice_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long offset = 0;
    unsigned long user_addr = vma->vm_start;
    void *kernel_addr;

    if (!va2sec_map || !va2sec_map->pages) {
        pr_err("Virt Addr to Sector memory not allocated\n");
        return -ENOMEM;
    }

    while (offset < size) {
        kernel_addr = (void *)((char *)va2sec_map->pages + offset);
        struct page *page = vmalloc_to_page(kernel_addr);
        if (!page)
            return -EFAULT;

        int ret = vm_insert_page(vma, user_addr, page);
        if (ret)
            return ret;

        user_addr += PAGE_SIZE;
        offset += PAGE_SIZE;
    }

    return 0;
}*/

static int wdevice_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long nr_pages = size >> PAGE_SHIFT;
    unsigned long user_addr = vma->vm_start;
    char *kernel_base = (char *)va2sec_map->pages;
    struct page *page;
    int ret;
    unsigned long i;

    if (!va2sec_map || !va2sec_map->pages) {
        pr_err("Virt Addr to Sector memory not allocated\n");
        return -ENOMEM;
    }

    if (size > va2sec_map->entry_count * sizeof(long)) {
        return -EINVAL;
    }

    // Optimize VM flags
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);

    // Use page-based iteration instead of byte-based
    for (i = 0; i < nr_pages; i++) {
        page = vmalloc_to_page(kernel_base + (i << PAGE_SHIFT));
        if (unlikely(!page))
            return -EFAULT;

        ret = vm_insert_page(vma, user_addr + (i << PAGE_SHIFT), page);
        if (unlikely(ret))
            return ret;
    }

    return 0;
}


static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = wdevice_open,
    .release = wdevice_release,
    .mmap = wdevice_mmap,
};



static int  bitmap_wdevice_init(void) /* Constructor */
{
	printk(KERN_INFO "Luc MAHOP: dbs_va2sec registered");
	if ((major = alloc_chrdev_region(&first, 0, 1, "dbs_va2sec")) < 0)
	{
		return major;
	}

	cdev_init(&c_dev, &fops);
    c_dev.owner = THIS_MODULE;
    cdev_add(&c_dev,first,1);
    pr_info("added char dev");

    wdbs_class = class_create(CLASS_NAME);
	if (IS_ERR(wdbs_class))
	{
		unregister_chrdev_region(first, 1);
		return PTR_ERR(wdbs_class);
	}
    pr_info("added class");
    wdbs_device = device_create(wdbs_class, NULL, first, NULL, "dbs_va2sec");
	if (IS_ERR(wdbs_device))
	{
		class_destroy(wdbs_class);
		unregister_chrdev_region(first, 1);
		return PTR_ERR(wdbs_device);
	}
    pr_info("added device");
    va2sec_map = pages_va_map_create(MAX_TRACKED_PAGES);
    if (!va2sec_map) {
        pr_err("Failed to create va2sec_map\n");
        pages_va_map_destroy(va2sec_map);
        return -ENOMEM;
    }
	return 0;
}

static void  bitmap_wdevice_exit(void) {
    device_destroy(wdbs_class, MKDEV(major, 0));
    class_destroy(wdbs_class);
    unregister_chrdev(major, DEVICE_NAME);
    pages_va_map_destroy(va2sec_map);
    pr_info("Hashmap module unloaded\n");
}


module_init(bitmap_wdevice_init);
module_exit(bitmap_wdevice_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to expose hashmap to user space with mmap");
