/**
 * This program is a Privileged Enclave demo in Hierarchical Deterministic Wallet case study,
 * which is supported to do nested account distribution and key derivation
 * 
 *  by Anonymous Author @ Sep 22, 2024.
*/
#include "eapp.h"
#include "privil.h"
#include "print.h"
#include "bip32_bip39.h"
#include "secp256k1.h" /* Fetch curve parameter locally */
#include "curves.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#define MAGIC_PEER_EID 4097
#define MAGIC_PAGE_ID  1

void __printHexData__(char * loghea,unsigned char  *pData, int nLen) {
	unsigned char *msg =  malloc(nLen * 2 + 1);
	memset(msg, 0, nLen * 2 + 1);
	HexToStr((char *)msg, pData, nLen);
	eapp_print("%s = %s ,len = %d \n",loghea,msg,nLen * 2);
	free(msg);
}

void print_HDNode(HDNode *node){
  eapp_print("[print_HDNode] depth = %d\n",node->depth);
  eapp_print("[print_HDNode] child_num = %d\n",node->child_num);
  __printHexData__("[print_HDNode] chain_code",node->chain_code,32);
  __printHexData__("[print_HDNode] private_key",node->private_key,32);
  __printHexData__("[print_HDNode] public_key",node->public_key,33);
}

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int execute(unsigned long * args)
{
  unsigned long begin_cycle, end_cycle;

  char *content = (char *)eapp_mmap(NULL, PAGE_SIZE);
  memset((void *)content, 0, PAGE_SIZE);
  uint32_t fingerpoint = 0;

  ocall_request_share_t share_req;
  share_req.eid = MAGIC_PEER_EID;
  share_req.share_id = MAGIC_PAGE_ID;
  share_req.share_content_ptr = (unsigned long)(content);
  share_req.share_size = PAGE_SIZE;

  ocall_request_t req;
  req.request = NE_REQUEST_ACQUIRE_PAGE;
  req.inspect_request = NULL;
  req.share_page_request = (unsigned long)(&share_req);
  
	begin_cycle = get_cycle();
  for (int x = 0 ; x < REPEAT_TIME ; x++)
  {
    eapp_pause_enclave((unsigned long)(&req));
    HDNode node;
    memcpy(&node, content, sizeof(HDNode));
    node.curve = &secp256k1_info; /* setup curve to secp256k1 */
    fingerpoint = hdnode_fingerprint(&node);
  }
	// eapp_print("%s\n", node.curve->bip32_name);
	end_cycle = get_cycle();
	eapp_print("ce: total_cycle: [%lx]\n", end_cycle - begin_cycle);


  // EAPP_RETURN(127);
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


int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
  test_verify_speed();
  EAPP_RETURN(0);
}
