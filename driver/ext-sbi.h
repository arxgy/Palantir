#ifndef _EXT_SBI
#define _EXT_SBI
// backend
#include <asm/sbi.h>
/*  not sure  */
#define EXT_SBI_EXT_ID 0x054b4248

#define EXT_SBI_SM_ACQ_AGENT 2077

struct sbiret sbi_sm_acquire_agent(unsigned long id) {
  return sbi_ecall(EXT_SBI_EXT_ID, 
                   EXT_SBI_SM_ACQ_AGENT, 
                   id, 0, 0, 0, 0, 0);
}

#endif
