#include "penglai-enclave.h"
#include "bip32_bip39.h"
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}


int execute(unsigned long * args)
{

	unsigned long begin_cycle, end_cycle;
	begin_cycle = get_cycle();

	const char *passphrase ="";
	int keylength = 64;
	int COIN_TYPE = 0;

	const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
	uint8_t bip39_seed[keylength];
	generateBip39Seeed(mnemonic,bip39_seed,passphrase);

	char rootkey[112];
	uint32_t fingerprint = 0;
	HDNode node;
	int r = hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &node);
	if( r != 1 ){
		printf("hdnode_from_seed failed (%d).", r);
		return -1;
	}
	
	for (int x = 0 ; x < REPEAT_TIME ; x++)
	{
		hdnode_fill_public_key(&node);
		hdnode_private_ckd(&node, 0);
		fingerprint = hdnode_fingerprint(&node);
	}


	end_cycle = get_cycle();
	printf("host: total_cycle: [%lx]\n", end_cycle - begin_cycle);
	return 0;
}

int main(){
  unsigned long * args;
  execute(args);
}
