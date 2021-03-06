#include "breakpoint.h"

#include <stdlib.h>
#include <stdio.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

struct _bp * bps = 0;



unsigned char breakpoint_get_byte (pid_t pid, uint64_t address)
{
    return ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
}


void breakpoint_set_byte (pid_t pid, uint64_t address, uint8_t byte)
{
    long bytes = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
    //printf("bytes=%x, address=%x\n", bytes, address);
    bytes = (bytes & (~0xff)) | byte;
    //printf("bytes are %x\n", bytes);
    ptrace(PTRACE_POKETEXT, pid, address, bytes);
}


int breakpoint_add (pid_t pid, uint64_t address)
{
    struct _bp * bp = (struct _bp *) malloc(sizeof(struct _bp));

    if (bps == NULL)
        bps = bp;
    else {
        struct _bp * next = bps;
        while (next->next != NULL) {
            if (    (next->pid == pid)
                 && (next->address == address)) {
                free(bp);
                return -1;
            }
            next = next->next;
        }
        next->next = bp;
    }
    
    bp->pid = pid;
    bp->address = address;
    bp->save_byte = breakpoint_get_byte(pid, address);
    bp->next = NULL;
    breakpoint_set_byte(pid, address, 0xcc);
        
    return 0;
}


int breakpoint_step (pid_t pid, uint64_t address)
{
    //printf("breakpoint_cont address=%llx\n", address);
    unsigned char save_byte = 0;
    
    struct _bp * next = bps;
    while (next != NULL) {
        if ((next->pid == pid) && (next->address + 1 == address)) {
            save_byte = next->save_byte;
            break;
        }
        next = next->next;
    }
    
    if (next == NULL)
        return -1;
        
    //printf("setting byte %x at %llx\n", save_byte, next->address);
    
    breakpoint_set_byte(pid, next->address, save_byte);
    
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    //printf("rip is %llx\n", regs.rip);
#ifdef LUADEBUG64
    regs.rip = (uint64_t) next->address;
#else
    regs.eip = (uint32_t) next->address;
#endif
    //printf("rip is %llx\n", regs.rip);

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    
    
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    
    int status;
    while (1) {
        waitpid(pid, &status, 0);
        //printf("WIFSTOPPED(status) = %d\n", WIFSTOPPED(status));
        //printf("WSTOPSIG(status) = %d %d\n", WSTOPSIG(status), SIGTRAP);
        if (WIFSTOPPED(status))
            break;
    }
    
    breakpoint_set_byte(pid, next->address, 0xcc);
    
    return 0;
}


int breakpoint_del (pid_t pid, uint64_t address)
{
    struct _bp * prev = bps;
    struct _bp * next = bps;
    
    while (next != NULL) {
        if ((next->pid == pid) && (next->address == address)) {
            if (prev != NULL)
                prev->next = next->next;
            if (bps == next)
                bps = next->next;
            free(next);
            return 0;
        }
        prev = next;
        next = next->next;
    }

    return -1;
}
