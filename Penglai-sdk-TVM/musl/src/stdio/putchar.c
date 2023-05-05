#include <stdio.h>
#include <string.h>
#include "putc.h"
#include "print.h"

// Penglai stdout
int putchar(int c)
{
	int r;
	char s[4];
	memcpy(s, &c, 4);
	eapp_print(s);
	return r;
	// return do_putc(c, stdout);
}
