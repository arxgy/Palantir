//#include "eapp.h"
//#include "print.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define test(p) (primes[p >> 6] & 1 << (p & 0x3f))
#define set(p) (primes[p >> 6] |= 1 << (p & 0x3f))
#define is_prime(p) !test(p)

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
			//eapp_print("%d\n", i);
			return 0;
		}
	}
    return 0;
}

//int EAPP_ENTRY main() {
int main() {
  //unsigned long * args;
  //EAPP_RESERVE_REG;

  unsigned long start_time;
  unsigned long end_time;
  asm volatile("rdcycle %0" : "=r"(start_time));

  primes();

  asm volatile("rdcycle %0" : "=r"(end_time));
  //eapp_print("primes finished in %ld cycles.\n", end_time - start_time);
  printf("primes-baseline finished in %ld cycles.\n", end_time - start_time);

  //EAPP_RETURN(0);
}
