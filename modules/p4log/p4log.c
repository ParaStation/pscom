/* Logging module 2002-11-20 jh */


#include <linux/kernel.h>   /* We're doing kernel work */
#include <linux/config.h>

#ifdef MODULE
#   include <linux/version.h>
#   include <linux/module.h>
#else
#   error Sorry, please compile as module!
#   define MOD_INC_USE_COUNT
#   define MOD_DEC_USE_COUNT
#   define MOD_IN_USE
#endif

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>    /* for verify_area */
#include <linux/errno.h> /* for -EBUSY */
#include <asm/segment.h> /* for put_user_byte */
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/sysctl.h>
//#include <asm/msr.h>
#include "ps_perf.h"

#include "p4linux.h"
#include "p4log.h"

#ifdef MODULE
MODULE_DESCRIPTION("Logging...") ;
MODULE_AUTHOR("jh ParTec AG Karlsruhe") ;
#endif



#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

/**
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * Returns 0 on success.
 */
static
int proc_dotest(ctl_table *table, int write, struct file *filp,
	       void *buffer, size_t *lenp)
{
    size_t len;
    int ret;

    if (write) goto err_nowrite;
    if (!lenp) goto err_nolenp;
#define TESTSTR "test 1234"
    len = MIN(*lenp, sizeof(TESTSTR));

    ret = copy_to_user(buffer, TESTSTR, len);

    if (ret) goto err_copytouser;
    *lenp = len;

//    current->state = TASK_INTERRUPTIBLE;
//    schedule_timeout(2*HZ);
    p4log(LOG_NOP, 0);
    return 0;

 err_nowrite:
    return -ENOSYS;
 err_nolenp:
    return -EINVAL;
 err_copytouser:
    return -EINVAL;
}


//#define LOGBUFSIZE 4096 /* Power of 2 ! */
#define LOGBUFSIZE 8192 /* Power of 2 ! */

static
spinlock_t loglock = SPIN_LOCK_UNLOCKED;
P4_WAITQ_HEADVAR(logwaitq);

static
struct logentry_s logbuffer[LOGBUFSIZE];

static
unsigned int logstart = 0;
unsigned int logend = 0;
unsigned int logoverrun = 0;

static
unsigned int p4_logcnt(void)
{
    return (logend - logstart) & (LOGBUFSIZE - 1);
}

static
void do_p4log(int type, long value)
{
    GET_CPU_CYCLES_LL(logbuffer[logend].time);
    logbuffer[logend].type = type;
    logbuffer[logend].value = value;
    logend = (logend + 1) & (LOGBUFSIZE - 1);
    if (logend == logstart) {
	/* overrun */
	logstart = (logstart + 1) & (LOGBUFSIZE - 1);
	logoverrun++;
	GET_CPU_CYCLES_LL(logbuffer[logstart].time);
	logbuffer[logstart].type = LOG_OVERRUN;
	logbuffer[logstart].value = logoverrun;
    }
    if (p4_logcnt() > LOGBUFSIZE/2) {
	P4_WAITQ_WAKEUP(logwaitq);
    }
}

void p4log(int type, long value)
{
    unsigned long flags;
    spin_lock_irqsave(&loglock, flags);
    do_p4log(type, value);
    spin_unlock_irqrestore(&loglock, flags);
}

/* cnt must be smaller than p4_logcnt */
static
int p4_readlog(void *buf, size_t cnt)
{
    size_t rest;
    logoverrun=0;

    rest = LOGBUFSIZE - logstart;
    if (rest <= cnt) {
	size_t size = rest * sizeof(logbuffer[0]);
	copy_to_user(buf, &logbuffer[logstart], size);
	logstart = 0;//(logstart + rest) & (LOGBUFSIZE - 1);
	buf += size;
	cnt -= rest;
    }
    if (cnt) {
	size_t size = cnt * sizeof(logbuffer[0]);
	copy_to_user(buf, &logbuffer[logstart], size);
	logstart = (logstart + cnt) & (LOGBUFSIZE - 1);
    }
    /* ToDo: Check return value from copy_to_user */
    return 0;
}

/**
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * Returns 0 on success.
 */
static
int proc_dolog(ctl_table *table, int write, struct file *filp,
	       void *buffer, size_t *lenp)
{
    size_t maxcnt;
    size_t mincnt;
    size_t cnt;
    int ret;
    unsigned long flags;

    if (write) goto err_nowrite;
    if (!lenp) goto err_nolenp;

    spin_lock_irqsave(&loglock, flags);
    maxcnt = *lenp / sizeof(logbuffer[0]);
    mincnt = MIN(maxcnt, LOGBUFSIZE / 2);
    cnt = p4_logcnt();

    if (mincnt > cnt) {
	P4_WAITQ_VAR(wait);
	/* wait maximal 5 sec for more data*/
	spin_unlock_irqrestore(&loglock, flags);

	current->state = TASK_INTERRUPTIBLE;
	P4_WAITQ_ADD(logwaitq, wait);
	schedule_timeout(5*HZ);
	P4_WAITQ_REMOVE(logwaitq, wait);

	spin_lock_irqsave(&loglock, flags);
	cnt = p4_logcnt();
    }

    /* copy logs: */
    cnt = MIN(maxcnt, cnt);
    ret = p4_readlog(buffer, cnt);
    if (ret) goto err_p4readlog;
    *lenp = cnt * sizeof(logbuffer[0]);

    do_p4log(LOG_READ, 0);
    spin_unlock_irqrestore(&loglock, flags);

    return 0;
 err_nowrite:
    return -ENOSYS;
 err_nolenp:
    return -EINVAL;
 err_p4readlog:
    return ret;
}

static struct ctl_table_header *sysctls_root_header = NULL;
static  ctl_table p4log_sysctls[] = {
    {
	ctl_name: 21151,
	procname: "info",
#define SYSINFO	"Compiled " __DATE__ " " __TIME__ " jh"
	data: SYSINFO,
	maxlen: sizeof(SYSINFO),
	mode:0444,
	child: 0,
	/*proc_handler:*/  &proc_dostring
    },{
	ctl_name: 21152,
	procname: "test",
	data: NULL,
	maxlen: 0,
	mode:0444,
	child: 0,
	/*proc_handler:*/  &proc_dotest
    },{
	ctl_name: 21153,
	procname: "log",
	data: NULL,
	maxlen: 0,
	mode:0444,
	child: 0,
	/*proc_handler:*/  &proc_dolog
    },{
	ctl_name: 0
    }
};




ctl_table  p4log_sysctl_root[] = {
    {
	ctl_name: 21061,
	procname: "p4log",
	data: NULL,
	maxlen: 0,
	mode:0555,
	child: p4log_sysctls,
    },{
	ctl_name: 0
    }
};


void cleanup_module(void){
    P4_WAITQ_WAKEUP(logwaitq);
    if (sysctls_root_header)
	unregister_sysctl_table(sysctls_root_header);
}


int init_module(void){
    printk(KERN_INFO "p4log installed\n");
    P4_WAITQ_INIT(logwaitq);
    sysctls_root_header = register_sysctl_table(p4log_sysctl_root,0);
    return 0;
}

P4_EXPORT_SYMBOL(p4log);
