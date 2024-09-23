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

#include <stdlib.h>
#include <string.h>

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

  EAPP_RETURN(127);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
