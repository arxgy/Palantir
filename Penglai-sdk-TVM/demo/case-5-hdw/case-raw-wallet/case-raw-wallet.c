/**
 * This program is a Privileged Enclave demo in Reusable Enclave case study,
 * which is supported to do nested attestation on a nested PE (reset module) and a NE (serverless payload w/o WASM runtime).
 * 
 *  by Anonymous Author @ Apr 4, 2024.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include "bip32_bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTRY_POINT 0x1000

void __printHexData__(char * loghea,unsigned char  *pData, int nLen) {
	unsigned char *msg =  malloc(nLen * 2 + 1);
	memset(msg, 0, nLen * 2 + 1);
	HexToStr((char *)msg, pData, nLen);
	eapp_print("%s = %s ,len = %d \n",loghea,msg,nLen * 2);
	free(msg);
}

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}
uint8_t msg[32];

void bench_secp256k1(void) {
	uint8_t sig[64], pub[33], pby;

	const ecdsa_curve *curve = &secp256k1;
	const uint8_t *priv = "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5";
	// memcpy(priv, , 32);
	ecdsa_get_public_key33(curve, priv, pub);

	// clock_t t = clock();
	unsigned long t_stamp = 0, t_sign = 0, t_verify = 0;
	for (int i = 0 ; i < 512; i++) {
		t_stamp = get_cycle();
		ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);
		t_sign += get_cycle() - t_stamp;

		t_stamp = get_cycle();
		int res = ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
		// assert(res == 0);
		t_verify += get_cycle() - t_stamp;
	}
	eapp_print("SECP256k1 signing time: %lx cycle\n", t_sign);
	eapp_print("SECP256k1 verifying time: %lx cycle\n", t_verify);

}

void bench_nist256p1(void) {
	uint8_t sig[64], pub[33], pby;

	const ecdsa_curve *curve = &nist256p1;
	const uint8_t *priv = "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5";
	// memcpy(priv, , 32);

	ecdsa_get_public_key33(curve, priv, pub);

	// unsigned long t = get_cycle();
	unsigned long t_stamp = 0, t_sign = 0, t_verify = 0;

	for (int i = 0 ; i < 512; i++) {
		t_stamp = get_cycle();
		ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);
		t_sign += get_cycle() - t_stamp;
		t_stamp = get_cycle();
		int res = ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
		// assert(res == 0);
		t_verify += get_cycle() - t_stamp;
	}
	eapp_print("NIST256p1 signing time: %lx cycle\n", t_sign);
	eapp_print("NIST256p1 verifying time: %lx cycle\n", t_verify);
}

void bench_ed25519(void) {
	ed25519_public_key pk;
	ed25519_secret_key sk;
	ed25519_signature sig;

	memcpy(pk, "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5", 32);
	ed25519_publickey(sk, pk);

	unsigned long t_stamp = 0, t_sign = 0, t_verify = 0;
	for (int i = 0 ; i < 512; i++) {
		t_stamp = get_cycle();
		ed25519_sign(msg, sizeof(msg), sk, pk, sig);
		t_sign += get_cycle() - t_stamp;

		t_stamp = get_cycle();
		int res = ed25519_sign_open(msg, sizeof(msg), pk, sig);
		// assert(res == 0);
		t_verify += get_cycle() - t_stamp;
	}

	eapp_print("Ed25519 signing time: %lx cycle\n", t_sign);
	eapp_print("Ed25519 verifying time: %lx cycle\n", t_verify);
}

void test_random_seed_speed()
{
	const char *passphrase ="";
  int keylength = 64;
  HDNode rootnode;

  const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
  uint8_t bip39_seed[keylength];

  unsigned long t_stamp = 0, t_seed = 0;
	t_stamp = get_cycle();
  for (int idx = 0 ; idx < REPEAT_TIME ; idx++)
  {
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &rootnode);
    hdnode_fill_public_key(&rootnode);
  }
	t_seed += get_cycle() - t_stamp;
  eapp_print("hdnode_from_seed (raw) time: %lx cycle\n", t_seed);
}

int execute(unsigned long * args)
{
  eapp_print("setup raw enclave end: %lx\n", get_cycle());
	unsigned long begin_cycle, end_cycle;
	const char *passphrase ="";
	int keylength = 64;
		int COIN_TYPE = 0;

	const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
	uint8_t bip39_seed[keylength];

  HDNode rootnode;

  unsigned long t_stamp = 0, t_seed = 0;
	t_stamp = get_cycle();
  for (int idx = 0 ; idx < REPEAT_TIME ; idx++)
  {
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &rootnode);
    hdnode_fill_public_key(&rootnode);
  }
	t_seed += get_cycle() - t_stamp;
  eapp_print("hdnode_from_seed (Native Enclave) time: %lx cycle\n", t_seed);

	generateBip39Seeed(mnemonic,bip39_seed,passphrase);

	char rootkey[112];
	uint32_t fingerprint = 0;
	HDNode node;
	int r = hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &node);
	if( r != 1 ){
		eapp_print("hdnode_from_seed failed (%d).", r);
		return -1;
	}
	hdnode_fill_public_key(&node);

	hdnode_private_ckd(&node, 0);//
	fingerprint = hdnode_fingerprint(&node);


	begin_cycle = get_cycle();

	for (int x = 0 ; x < REPEAT_TIME ; x++)
	{
		hdnode_private_ckd(&node, 0);//
		node.curve = &secp256k1_info; /* setup curve to secp256k1 */
		fingerprint = hdnode_fingerprint(&node);

	}

	end_cycle = get_cycle();



	eapp_print("raw: total_cycle: [%lx]\n", end_cycle - begin_cycle);

}

int execute_single(unsigned long * args)
{
	unsigned long begin_cycle, end_cycle;
	begin_cycle = get_cycle();
	const char *passphrase ="";
	int keylength = 64;
		int COIN_TYPE = 0;

	const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
	uint8_t bip39_seed[keylength];

  HDNode rootnode;


	for (int x = 0 ; x < REPEAT_TIME ; x++)
	{
  // unsigned long t_stamp = 0, t_seed = 0;
  // for (int idx = 0 ; idx < REPEAT_TIME ; idx++)
  // {
    // t_stamp = get_cycle();
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &rootnode);
    hdnode_fill_public_key(&rootnode);
    // t_seed += get_cycle() - t_stamp;
  // }
  // eapp_print("hdnode_from_seed (Native Enclave) time: %lx cycle\n", t_seed);

		generateBip39Seeed(mnemonic,bip39_seed,passphrase);

		char rootkey[112];
		uint32_t fingerprint = 0;
		HDNode node;
		int r = hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &node);
		if( r != 1 ){
			eapp_print("hdnode_from_seed failed (%d).", r);
			return -1;
		}
		hdnode_fill_public_key(&node);


		hdnode_private_ckd(&node, 0);//
		fingerprint = hdnode_fingerprint(&node);
		hdnode_private_ckd(&node, 0);//
		node.curve = &secp256k1_info; /* setup curve to secp256k1 */
		fingerprint = hdnode_fingerprint(&node);

	}

	end_cycle = get_cycle();



	eapp_print("single-to-single: total_cycle: [%lx]\n", end_cycle - begin_cycle);

}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
	execute_single(args);
	// test_random_seed_speed();
	// bench_secp256k1();
	// bench_nist256p1();
	// bench_ed25519();

  EAPP_RETURN(0);
}
