#include "stdio_impl.h"
#include "string.h"

extern void eapp_puts(const char*s, ...);
// Penglai stdout
int puts(const char *s)
{
	int r;
	eapp_puts(s);
	return r;
	// FLOCK(stdout);
	// r = -(fputs(s, stdout) < 0 || putc_unlocked('\n', stdout) < 0);
	// FUNLOCK(stdout);
	// return r;
}
