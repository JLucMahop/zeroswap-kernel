// myvals.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include "myvals.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("example");
MODULE_DESCRIPTION("Expose 3 kernel values via sysfs and procfs");

unsigned long long host_out_total = 0;
unsigned long long host_in_total = 0;
unsigned long long host_blank_realloc = 0;

DEFINE_MUTEX(vals_lock);
static struct kobject *my_kobj;
static struct proc_dir_entry *proc_entry;

/*
 * Per-attribute container that maps a sysfs object to the target variable.
 */
struct v_attr {
    struct kobj_attribute attr;
    unsigned long long *target;
};

#define DEFINE_V_ATTR(name, ptr) \
    static struct v_attr name##_vattr = { __ATTR(name, 0644, v_show, v_store), ptr }

/* Predeclare callbacks */
static ssize_t v_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t v_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);

/* Create 3 sysfs attributes, each mapped to its respective variable */
DEFINE_V_ATTR(v1, &host_out_total);
DEFINE_V_ATTR(v2, &host_in_total);
DEFINE_V_ATTR(v3, &host_blank_realloc);

/* --- Sysfs show/store --- */
static ssize_t v_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct v_attr *v = container_of(attr, struct v_attr, attr);
    unsigned long long tmp;

    mutex_lock(&vals_lock);
    tmp = *(v->target);
    mutex_unlock(&vals_lock);

    return scnprintf(buf, PAGE_SIZE, "%llu\n", tmp);
}

static ssize_t v_store(struct kobject *kobj, struct kobj_attribute *attr,
                       const char *buf, size_t count)
{
    struct v_attr *v = container_of(attr, struct v_attr, attr);
    unsigned long long newv;

    if (kstrtoull(buf, 10, &newv))
        return -EINVAL;

    mutex_lock(&vals_lock);
    *(v->target) = newv;
    mutex_unlock(&vals_lock);

    return count;
}

/* --- Procfs: show all three at once --- */
static int myvals_proc_show(struct seq_file *m, void *v)
{
    mutex_lock(&vals_lock);
    seq_printf(m, "v1=%llu\nv2=%llu\nv3=%llu\n",
               host_out_total, host_in_total, host_blank_realloc);
    mutex_unlock(&vals_lock);
    return 0;
}

static int myvals_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, myvals_proc_show, NULL);
}

static const struct proc_ops myvals_proc_fops = {
    .proc_open = myvals_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* --- Module init/exit --- */
static int __init myvals_init(void)
{
    int ret;

    my_kobj = kobject_create_and_add("myvals", kernel_kobj); // /sys/kernel/myvals
    if (!my_kobj) {
        pr_err("myvals: failed to create kobject\n");
        return -ENOMEM;
    }

    ret = sysfs_create_file(my_kobj, &v1_vattr.attr.attr);
    if (ret) goto err_kobj;
    ret = sysfs_create_file(my_kobj, &v2_vattr.attr.attr);
    if (ret) goto err_files;
    ret = sysfs_create_file(my_kobj, &v3_vattr.attr.attr);
    if (ret) goto err_files;

    proc_entry = proc_create("myvals", 0444, NULL, &myvals_proc_fops); // /proc/myvals
    if (!proc_entry) {
        ret = -ENOMEM;
        goto err_files;
    }

    pr_info("myvals: loaded\n");
    return 0;

err_files:
    sysfs_remove_file(my_kobj, &v1_vattr.attr.attr);
    sysfs_remove_file(my_kobj, &v2_vattr.attr.attr);
    sysfs_remove_file(my_kobj, &v3_vattr.attr.attr);
err_kobj:
    kobject_put(my_kobj);
    return ret;
}

static void __exit myvals_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);

    sysfs_remove_file(my_kobj, &v1_vattr.attr.attr);
    sysfs_remove_file(my_kobj, &v2_vattr.attr.attr);
    sysfs_remove_file(my_kobj, &v3_vattr.attr.attr);
    kobject_put(my_kobj);

    pr_info("myvals: unloaded\n");
}

module_init(myvals_init);
module_exit(myvals_exit);
