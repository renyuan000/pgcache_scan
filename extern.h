#ifndef __EXTERN_H
#define __EXTERN_H

#include "include.h"

extern unsigned long kallsyms_lookup_name_addr;
extern int get_kallsyms_lookup_name_function(void);


/* sysctl */
extern int sysctl_rto_backoff;
extern int sysctl_rto_min;
extern int sysctl_init_cwnd;
extern int sysctl_loss_backoff;
extern int sysctl_quick_start;
extern int sysctl_init_rtt_interval;
extern void tcpspeed_sysctl_register(void);
extern void tcpspeed_sysctl_unregister(void);

/* debug sysctl */
extern int sysctl_debug_level;
extern int sysctl_debug_except_port;
extern int sysctl_debug_port;



#endif
