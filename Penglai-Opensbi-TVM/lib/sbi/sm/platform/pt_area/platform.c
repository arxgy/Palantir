#include "sm/platform/pt_area/platform_thread.h"
#include "sm/pmp.h"
#include "sm/sm.h"

/**
 * \brief It uses two PMP regions.
 * Region-0 is for protecting secure monitor's memory
 * Region-last is for allowing host kernel to access any other mem.
 *
 */
int platform_init()
{
  clear_pmp(0);

  //config the PMP 0 to protect security monitor
  struct pmp_config_t pmp_config;
  pmp_config.paddr = (uintptr_t)SM_BASE;
  pmp_config.size = (unsigned long)SM_SIZE;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_NO_PERM;
  set_pmp(0, pmp_config);

  //config the last PMP to allow kernel to access memory
  pmp_config.paddr = 0;
  pmp_config.size = -1UL;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_R | PMP_W | PMP_X;
  set_pmp(NPMP-1, pmp_config);

  return 0;
}
