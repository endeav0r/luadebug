#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

struct _debug {
	pid_t pid;
	int status;
};

int l_debug_new (lua_State * L);

struct _debug * l_check_debug (lua_State * L, int position);

int l_debug_execv     (lua_State * L);

int l_debug_pid       (lua_State * L);
int l_debug_getpc     (lua_State * L);
int l_debug_registers (lua_State * L);
int l_debug_wait      (lua_State * L);
int l_debug_readmem   (lua_State * L);
int l_debug_step      (lua_State * L);

int l_debug_termsig   (lua_State * L);
int l_debug_stopsig   (lua_State * L);
int l_debug_status    (lua_State * L);

int l_debug_breakpoint (lua_State * L);
