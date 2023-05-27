#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include "eapp.h"
#include "print.h"

#define test(p) (primes[p >> 6] & 1 << (p & 0x3f))
#define set(p) (primes[p >> 6] |= 1 << (p & 0x3f))
#define is_prime(p) !test(p)

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int primes()
{
	int limit = 33333333;
	size_t primes_size = ((limit >> 6) + 1) * sizeof(uint64_t);
	uint64_t *primes = (uint64_t*)malloc(primes_size);
	int64_t p = 2, sqrt_limit = (int64_t)sqrt(limit);
	while (p <= limit >> 1) {
		for (int64_t n = 2 * p; n <= limit; n += p) if (!test(n)) set(n);
		while (++p <= sqrt_limit && test(p));
	}
	for (int i = limit; i > 0; i--) {
		if (is_prime(i)) {
			//printf("%d\n", i);
			
		}
	}
}
int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  unsigned long begin_cycle, end_cycle;
  begin_cycle = get_cycle();
  primes(args);
  end_cycle = get_cycle();
  eapp_print("[primes] Running takes (cycles): %lx\n", end_cycle-begin_cycle);
  EAPP_RETURN(end_cycle-begin_cycle);
}
