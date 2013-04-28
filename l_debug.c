#include "l_debug.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct luaL_Reg l_debug_f [] = {
    {"execv", l_debug_execv},
    {NULL, NULL}    
};

static const struct luaL_Reg l_debug_m [] = {
    {"pid",       l_debug_pid},
    {"registers", l_debug_registers},
    {"wait",      l_debug_wait},
    {"readmem",   l_debug_readmem},
    {"termsig",   l_debug_termsig},
    {"stopsig",   l_debug_stopsig},
    {"status",    l_debug_status},
    {NULL, NULL}
};

LUALIB_API int luaopen_l_debug (lua_State * L)
{
    luaL_newmetatable(L, "l.debug_t");
    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);
    luaL_register(L, NULL, l_debug_m);
    luaL_register(L, "l_debug", l_debug_f);

    return 2;
}


int l_debug_new (lua_State * L)
{
    struct _debug * d = lua_newuserdata(L, sizeof(struct _debug));
    luaL_getmetatable(L, "l.debug_t");
    lua_setmetatable(L, -2);
    d->pid = -1;

    return 1;
}


struct _debug * l_check_debug (lua_State * L, int position)
{
    void * userdata = luaL_checkudata(L, position, "l.debug_t");
    luaL_argcheck(L, userdata != NULL, position, "l.debug_t expected");
    return (struct _debug *) userdata;
}


int l_debug_execv (lua_State * L)
{
    // grab arguments for execv
    const char * path = luaL_checkstring(L, -2);

    if (lua_istable(L, -1) == 0) {
        luaL_error(L, "Expected table of arguments");
        return 0;
    }

    int table_len = lua_objlen(L, -1);
    char ** args = (char **) malloc(sizeof(char *) * (table_len + 2));

    args[0] = strdup(path);

    int i;
    for (i = 1; i < table_len + 1; i++) {
        lua_pushvalue(L, -1);
        lua_rawgeti(L, -1, i);
        args[i] = strdup(luaL_checkstring(L, -1));
        lua_pop(L, 1);
    }
    args[i] = NULL;

    // fork process
    pid_t pid = fork();

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
            luaL_error(L, "debug ptrace error");
        if (execv(path, args)) {
            char tmp[256];
            char * errorstr = "UNKNOWN";
            switch (errno) {
            case ENODEV : errorstr  = "ENODEV"; break;
            case ENOTDIR : errorstr = "ENOTDIR"; break;
            case ENOENT : errorstr  = "ENOENT"; break;
            case EISDIR : errorstr  = "EISDIR"; break;
            case ENOEXEC : errorstr = "ENOEXEC"; break;
            case ENOMEM : errorstr  = "ENOMEM"; break;
            case EFAULT : errorstr  = "EFAULT"; break;
            }
            snprintf(tmp, 256, "execv error %s", errorstr);
            luaL_error(L, tmp);
        }
    }

    for (i = 0; i < table_len + 1; i++) {
        free(args[i]);
    }
    free(args);

    int status;
    while (1) {
        waitpid(pid, &status, 0);
        if ((WIFSTOPPED(status)) && (WSTOPSIG(status) == SIGTRAP))
            break;
    }

    lua_pop(L, 2);
    l_debug_new(L);

    struct _debug * d = l_check_debug(L, -1);
    d->pid = pid;
    d->status = status;

    return 1;
}


int l_debug_pid (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);
    lua_pop(L, 1);
    lua_pushinteger(L, d->pid);
    return 1;
}

int l_debug_registers (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);
    lua_pop(L, 1);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, d->pid, NULL, &regs);

    lua_newtable(L);

    char tmp[64];

#define PUSHREGTABLE(XX) \
    snprintf(tmp, 64, "%016llx", regs.XX);\
    lua_pushstring(L, #XX);\
    lua_pushstring(L, tmp);\
    lua_settable(L, -3);

    PUSHREGTABLE(rax)
    PUSHREGTABLE(rbx)
    PUSHREGTABLE(rcx)
    PUSHREGTABLE(rdx)
    PUSHREGTABLE(rsi)
    PUSHREGTABLE(rdi)
    PUSHREGTABLE(rsp)
    PUSHREGTABLE(rbp)
    PUSHREGTABLE(r8)
    PUSHREGTABLE(r9)
    PUSHREGTABLE(r10)
    PUSHREGTABLE(r11)
    PUSHREGTABLE(r12)
    PUSHREGTABLE(r13)
    PUSHREGTABLE(r14)
    PUSHREGTABLE(r15)
    PUSHREGTABLE(rip)

    return 1;
}

int l_debug_wait (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);

    lua_pop(L, 1);

    ptrace(PTRACE_CONT, d->pid, NULL, NULL);
    waitpid(d->pid, &(d->status), 0);

    if (WIFEXITED(d->status))
        lua_pushstring(L, "WIFEXITED");
    else if (WIFSIGNALED(d->status))
        lua_pushstring(L, "WIFSIGNALED");
    else if (WIFSTOPPED(d->status))
        lua_pushstring(L, "WIFSTOPPED");
    else
        lua_pushstring(L, "W_OTHER");

    return 1;
}


int l_debug_readmem (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -3);

    lua_Number address_number = luaL_checknumber(L, -2);
    uint64_t address = (uint64_t) address_number;

    unsigned int bytes = luaL_checkinteger(L, -1);

    lua_pop(L, 3);

    lua_newtable(L);

    unsigned int i;
    for (i = 0; i < bytes; i++) {
        long result = ptrace(PTRACE_PEEKTEXT, d->pid, address + i, NULL);
        lua_pushinteger(L, i + 1);
        lua_pushinteger(L, result & 0xff);
        lua_settable(L, -3);
    }

    return 1;
}


int l_debug_termsig (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);

    lua_pop(L, 1);

    lua_pushinteger(L, WTERMSIG(d->status));

    return 1;
}


int l_debug_stopsig (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);

    lua_pop(L, 1);

    lua_pushinteger(L, WSTOPSIG(d->status));

    return 1;
}


int l_debug_status (lua_State * L)
{
    struct _debug * d = l_check_debug(L, -1);

    lua_pop(L, 1);

    lua_pushinteger(L, d->status);

    return 1;   
}