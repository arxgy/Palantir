#include "sm/platform/pt_area/platform_thread.h"
#include "sm/enclave.h"
#include "sbi/riscv_encoding.h"

void platform_enter_enclave_world()
{
  // TODO: add register to indicate whether in encalve world or not
  return;
}

void platform_exit_enclave_world()
{
  // TODO: add register to indicate whether in encalve world or not
  return;
}

int platform_check_in_enclave_world()
{
  // TODO: add register to indicate whether in encalve world or not
  return 0;
}

/**
 * \brief Compare the used satp and the enclave ptbr (encl_ptr)
 * It's supposed to be equal.
 *
 * \param enclave the check enclave
 */
int platform_check_enclave_authentication(struct enclave_t* enclave)
{
  if(enclave->thread_context.encl_ptbr != csr_read(CSR_SATP))
    return -1;
  return 0;
}

/**
 * \brief Switch to enclave's ptbr (enclave_ptbr).
 *
 * \param thread the current enclave thread.
 * \param enclave_ptbr the  enclave ptbr value.
 */
void platform_switch_to_enclave_ptbr(struct thread_state_t* thread, uintptr_t enclave_ptbr)
{
  csr_write(CSR_SATP, enclave_ptbr);
}

/**
 * \brief Switch to host's ptbr (host_ptbr).
 *
 * \param thread the current enclave thread.
 * \param host_ptbr the  host ptbr value.
 */
void platform_switch_to_host_ptbr(struct thread_state_t* thread, uintptr_t host_ptbr)
{
  csr_write(CSR_SATP, host_ptbr);
}
