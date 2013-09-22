#ifndef bp_HEADER
#define bp_HEADER

#include <sys/ptrace.h>
#include <sys/types.h>
#include <inttypes.h>

struct _bp {
    pid_t pid;
    uint64_t address;
    unsigned char save_byte;
    struct _bp * next;
};

int breakpoint_add  (pid_t pid, uint64_t address);
int breakpoint_cont (pid_t pid, uint64_t address);
int breakpoint_del  (pid_t pid, uint64_t address);

#endif
