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

int execute(unsigned long * args)
{
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
		eapp_print("hdnode_from_seed failed (%d).", r);
		return -1;
	}
	hdnode_fill_public_key(&node);

	r = hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey, sizeof(rootkey));
	if ( r <= 0 ){
		eapp_print("hdnode_serialize_private failed (%d).", r);
		return -1;
	}

	eapp_print("root private key:%s\n",rootkey);

	r = hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey, sizeof(rootkey));
	if (r <= 0) {
	   eapp_print("hdnode_serialize_public failed (%d).", r);
	   return -1;
	}
	eapp_print("root  public key:%s\n",rootkey);

	// m/44'/coin/0'/0/0   m/49/coin/0/0/0
	hdnode_private_ckd_prime(&node, 44);
  hdnode_private_ckd_prime(&node, COIN_TYPE);
	hdnode_private_ckd_prime(&node, 0);
	hdnode_private_ckd(&node, 0);
	fingerprint = hdnode_fingerprint(&node);
	hdnode_private_ckd(&node, 0);
	hdnode_fill_public_key(&node);

	hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey, sizeof(rootkey));
	if (r <= 0) {
		eapp_print("hdnode_serialize_private failed (%d).", r);
	   return -1;
	}
	__printHexData__("child hex private key = ", (unsigned char *)node.private_key, 32);

	hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey, sizeof(rootkey));
	if (r <= 0) {
		eapp_print("hdnode_serialize_public failed (%d).", r);
	   return -1;
	 }
	__printHexData__("child hex public key = ", (unsigned char *)node.public_key, 33);

  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
