#ifndef  _EAPP_COMMON
#define _EAPP_COMMON
#include "attest.h"

/* default layout of enclave */
//#####################
//#   reserved for    #
//#       s mode      #
//##################### 0xffffffe000000000 //actually this is the start address of kernel's image
//#       hole        #
//##################### 0x0000004000000000
//#    shared mem     #
//#     with host     #
//##################### 0x0000003900000000
//#                   #
//#    host mm arg    #
//#                   #
//##################### 0x0000003800000000
//#                   #
//#       stack       #
//#                   #
//##################### 0x0000003000000000
//#       mmap        #
//#                   #
//##################### brk
//#                   #
//#       heap        #
//#                   #
//##################### 0x0000001000000000
//#                   #
//#   text/code/bss   #
//#                   #
//##################### 0x0000000000001000 //not fixed, depends on enclave's lds
//#       hole        #
//##################### 0x0
struct call_enclave_arg_t
{
  unsigned long req_arg;
  unsigned long resp_val;
  unsigned long req_vaddr;
  unsigned long req_size;
  unsigned long resp_vaddr;
  unsigned long resp_size;
};


void EAPP_RETURN(unsigned long retval) __attribute__((noreturn));
void SERVER_RETURN(struct call_enclave_arg_t *arg) __attribute__((noreturn));
//unsigned long EAPP_OCALL(unsigned long ocall_func_id);
void* EAPP_MMAP(unsigned long ocall_func_id, void* vaddr, unsigned long size);
int EAPP_UNMAP(unsigned long ocall_func_id, void* vaddr, unsigned long size);
int EAPP_PERSISTENCY_WRITE_SEC(unsigned long ocall_func_id, unsigned long sec);
int EAPP_PERSISTENCY_READ_SEC(unsigned long ocall_func_id, unsigned long sec);
unsigned long EAPP_ACQUIRE_ENCLAVE(char* name);
unsigned long EAPP_GET_CALLER_ID();
unsigned long EAPP_GET_ENCLAVE_ID();
unsigned long EAPP_CALL_ENCLAVE(unsigned long handle, struct call_enclave_arg_t *arg);
int EAPP_YIELD();
int EAPP_GET_REPORT(char * name, struct report_t *report, unsigned long nonce);
int EAPP_GET_KEY(int ket_type, char *key, int key_size);

void* eapp_mmap(void* vaddr, unsigned long size);
int eapp_unmap(void* vaddr, unsigned long size);
void* sbrk(long size);

int eapp_return_relay_page();
unsigned long split_mem_region(unsigned long mem_addr, unsigned long mem_size, unsigned long split_addr);

int get_report(char* name, struct report_t *report, unsigned long nonce);
int get_key(int ket_type, char *key, int key_size);
unsigned long acquire_enclave(char* name);
unsigned long get_caller_id();
unsigned long get_enclave_id();
unsigned long call_enclave(unsigned long handle, struct call_enclave_arg_t* arg);
unsigned long asyn_enclave_call(char* name, struct call_enclave_arg_t *arg);

int eapp_persistency_read_sec(unsigned long sec);
int eapp_persistency_write_sec(unsigned long sec);

#define ROUNDUP(size, align) (((size-1)/align+1)*align)
#define RISCV_PAGE_SIZE 4096
#define EAPP_ENTRY __attribute__((__section__(".text._start")))
#define EAPP_RESERVE_REG   asm volatile("addi sp,sp,-256\n\t" \
                                                                                            "sd ra, 1*8(sp)\n\t" \
                                                                                            "sd gp, 3*8(sp)\n\t" \
                                                                                            "sd tp, 4*8(sp)\n\t" \
                                                                                            "sd t0, 5*8(sp)\n\t" \
                                                                                            "sd t1, 6*8(sp)\n\t" \
                                                                                            "sd t2, 7*8(sp)\n\t" \
                                                                                            "sd s0, 8*8(sp)\n\t" \
                                                                                            "sd s1, 9*8(sp)\n\t" \
                                                                                            "sd a0, 10*8(sp)\n\t" \
                                                                                            "sd a1, 11*8(sp)\n\t" \
                                                                                            "sd a2, 12*8(sp)\n\t" \
                                                                                            "sd a3, 13*8(sp)\n\t" \
                                                                                            "sd a4, 14*8(sp)\n\t" \
                                                                                            "sd a5, 15*8(sp)\n\t" \
                                                                                            "sd a6, 16*8(sp)\n\t" \
                                                                                            "sd a7, 17*8(sp)\n\t" \
                                                                                            "sd s2, 18*8(sp)\n\t" \
                                                                                            "sd s3, 19*8(sp)\n\t" \
                                                                                            "sd s4, 20*8(sp)\n\t" \
                                                                                            "sd s5, 21*8(sp)\n\t" \
                                                                                            "sd s6, 22*8(sp)\n\t" \
                                                                                            "sd s7, 23*8(sp)\n\t" \
                                                                                            "sd s8, 24*8(sp)\n\t" \
                                                                                            "sd s9, 25*8(sp)\n\t" \
                                                                                            "sd s10, 26*8(sp)\n\t" \
                                                                                            "sd s11, 27*8(sp)\n\t" \
                                                                                            "sd t3, 28*8(sp)\n\t" \
                                                                                            "sd t4, 29*8(sp)\n\t" \
                                                                                            "sd t5, 30*8(sp)\n\t" \
                                                                                            "sd t6, 31*8(sp)\n\t" \
                                                                                            "mv %0 ,sp":"=r "(args) )

#endif
