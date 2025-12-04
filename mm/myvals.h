#ifndef MYVALS_H
#define MYVALS_H

#include <linux/mutex.h>
extern struct mutex vals_lock;
extern unsigned long long host_out_total;
extern unsigned long long host_in_total;
extern unsigned long long host_blank_realloc;

#endif // MYVALS_H
