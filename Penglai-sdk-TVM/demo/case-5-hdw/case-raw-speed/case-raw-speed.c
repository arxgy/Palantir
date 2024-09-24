#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "eapp.h"
#include "print.h"
#include "bip32_bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519.h"

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

uint8_t msg[32];

void prepare_msg(void)
{
	for (size_t i = 0; i < sizeof(msg); i++) {
		msg[i] = i * 1103515245;
	}
}

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

void test_verify_speed(void) {
	prepare_msg();
	bench_secp256k1();
	bench_nist256p1();
	bench_ed25519();
}

HDNode root;

void prepare_node(void)
{
	hdnode_from_seed((uint8_t *)"NothingToSeeHere", 16, SECP256K1_NAME, &root);
}

// void bench_ckd_normal(void) {
// 	char addr[40];
// 	unsigned long t = get_cycle();
// 	for (int i = 0; i < 1024; i++) {
// 		HDNode node = root;
// 		hdnode_public_ckd(&node, i);
// 		ecdsa_get_address(node.public_key, 0, addr, 40);
// 		if (i == 0) {
// 			eapp_print("address = %s\n", addr);
// 		}
// 	}
// 	eapp_print("CKD normal time: %lx cycle\n", get_cycle() - t);
// }

// void bench_ckd_optimized(void) {
// 	char addr[40];
// 	curve_point pub;
// 	ecdsa_read_pubkey(0, root.public_key, &pub);
// 	// clock_t t = clock();
// 	unsigned long t = get_cycle();
// 	for (int i = 0; i < 1024; i++) {
// 		hdnode_public_ckd_address_optimized(&pub, root.public_key, root.chain_code, i, 0, addr, 40);
// 		if (i == 0) {
// 			eapp_print("address = %s\n", addr);
// 		}
// 	}
// 	eapp_print("CKD optim speed: %lx cycle\n", get_cycle() - t);
// 	// eapp_print("CKD optim speed: %0.2f iter/s\n", 1000.0f / ((float)(clock() - t) / CLOCKS_PER_SEC));
// }

// void test_ckd_speed(void) {
// 	prepare_node();
// 	bench_ckd_normal();
// 	bench_ckd_optimized();
// }


void test_random_seed_speed()
{
	const char *passphrase ="";
  int keylength = 64;
  HDNode rootnode;

  const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
  uint8_t bip39_seed[keylength];

  unsigned long t_stamp = 0, t_seed = 0;
  for (int idx = 0 ; idx < REPEAT_TIME ; idx++)
  {
    t_stamp = get_cycle();
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &rootnode);
    hdnode_fill_public_key(&rootnode);
    t_seed += get_cycle() - t_stamp;
  }
  eapp_print("hdnode_from_seed (raw) time: %lx cycle\n", t_seed);
}

int execute(unsigned long * args) {
	test_random_seed_speed();
	test_verify_speed();
	// test_ckd_speed();
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}