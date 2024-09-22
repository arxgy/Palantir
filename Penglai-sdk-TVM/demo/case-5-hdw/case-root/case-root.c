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

void print_HDNode(HDNode *node){
  eapp_print("[print_HDNode] depth = %d\n",node->depth);
  eapp_print("[print_HDNode] child_num = %d\n",node->child_num);
  __printHexData__("[print_HDNode] chain_code",node->chain_code,32);
  __printHexData__("[print_HDNode] private_key",node->private_key,32);
  __printHexData__("[print_HDNode] public_key",node->public_key,33);
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

  EAPP_RETURN(0);

}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
