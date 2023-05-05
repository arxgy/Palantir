#include "sbi/sbi_ipi_destroy_enclave.h"
#include "sm/ipi.h"
#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_ipi_destroy_enclave.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_hartmask.h>
#include <sm/enclave.h>

static unsigned long ipi_destroy_enclave_data_offset;
static unsigned long ipi_destroy_enclave_sync_offset;

#define SBI_IPI_DESTROY_ENCLAVE_DATA_INIT(__p, __host_ptbr, __enclave_id, __src) \
do { \
	(__p)->host_ptbr = (__host_ptbr); \
	(__p)->enclave_id = (__enclave_id); \
	SBI_HARTMASK_INIT_EXCEPT(&(__p)->smask, (__src)); \
} while (0)

void set_ipi_destroy_enclave_and_sync(u32 remote_hart, ulong host_ptbr, int enclave_id)
{
  struct ipi_destroy_enclave_data_t ipi_destroy_enclave_data;
  u32 source_hart = current_hartid();

  //sync all other harts
  SBI_IPI_DESTROY_ENCLAVE_DATA_INIT(&ipi_destroy_enclave_data, host_ptbr, enclave_id, source_hart);
  sbi_send_ipi_destroy_enclave((0x1<<remote_hart), 0, &ipi_destroy_enclave_data);
  return;
}

static void sbi_eprocess_ipi_destroy_enclave(struct sbi_scratch *scratch, struct sbi_trap_regs* regs)
{
	struct ipi_destroy_enclave_data_t *data = sbi_scratch_offset_ptr(scratch, ipi_destroy_enclave_data_offset);
	struct sbi_scratch *rscratch = NULL;
	u32 rhartid;
	unsigned long *ipi_destroy_enclave_sync = NULL;
	ipi_destroy_enclave((uintptr_t *)regs, data->host_ptbr, data->enclave_id);
	//sync
	sbi_hartmask_for_each_hart(rhartid, &data->smask) {
		rscratch = sbi_hartid_to_scratch(rhartid);
		if (!rscratch)
			continue;
		ipi_destroy_enclave_sync = sbi_scratch_offset_ptr(rscratch, ipi_destroy_enclave_sync_offset);
		while (atomic_raw_xchg_ulong(ipi_destroy_enclave_sync, 1));
	}
}

static void sbi_process_ipi_destroy_enclave(struct sbi_scratch *scratch)
{
	return;
}

static int sbi_update_ipi_destroy_enclave(struct sbi_scratch *scratch,
			  struct sbi_scratch *remote_scratch,
			  u32 remote_hartid, void *data)
{
	struct ipi_destroy_enclave_data_t *ipi_destroy_enclave_data = NULL;
	u32 curr_hartid = current_hartid();

	if (remote_hartid == curr_hartid) {
		sbi_bug("M mode: sbi_update_ipi_destroy_enclave: remote_hartid is current hartid\n");
		return -1;
	}

	ipi_destroy_enclave_data = sbi_scratch_offset_ptr(remote_scratch, ipi_destroy_enclave_data_offset);
	//update the remote hart ipi_destroy_enclave data
	sbi_memcpy(ipi_destroy_enclave_data, data, sizeof(struct ipi_destroy_enclave_data_t));

	return 0;
}

static void sbi_ipi_destroy_enclave_sync(struct sbi_scratch *scratch)
{
	unsigned long *ipi_destroy_enclave_sync =
			sbi_scratch_offset_ptr(scratch, ipi_destroy_enclave_sync_offset);
	//wait the remote hart process the ipi_destroy_enclave signal
	while (!atomic_raw_xchg_ulong(ipi_destroy_enclave_sync, 0));
	return;
}

static struct sbi_ipi_event_ops ipi_destroy_enclave_ops = {
	.name = "IPI_DESTROY_ENCLAVE",
	.update = sbi_update_ipi_destroy_enclave,
	.sync = sbi_ipi_destroy_enclave_sync,
	.process = sbi_process_ipi_destroy_enclave,
	.e_process = sbi_eprocess_ipi_destroy_enclave,
};

static u32 ipi_destroy_enclave_event = SBI_IPI_EVENT_MAX;

int sbi_send_ipi_destroy_enclave(ulong hmask, ulong hbase, struct ipi_destroy_enclave_data_t* ipi_destroy_enclave_data)
{
	return sbi_ipi_send_many(hmask, hbase, ipi_destroy_enclave_event, ipi_destroy_enclave_data);
}

int sbi_ipi_destroy_enclave_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int ret;
	struct ipi_destroy_enclave_data_t *ipi_destroy_enclave_data;
	unsigned long *ipi_destroy_enclave_sync;
	if (cold_boot) {
        // Define the ipi_destroy_enclave data offset in the scratch
		ipi_destroy_enclave_data_offset = sbi_scratch_alloc_offset(sizeof(*ipi_destroy_enclave_data),
							    "IPI_DESTROY_ENCLAVE_DATA");
		if (!ipi_destroy_enclave_data_offset)
			return SBI_ENOMEM;

		ipi_destroy_enclave_sync_offset = sbi_scratch_alloc_offset(sizeof(*ipi_destroy_enclave_sync),
							    "IPI_DESTROY_ENCLAVE_SYNC");
		if (!ipi_destroy_enclave_sync_offset)
			return SBI_ENOMEM;

		ipi_destroy_enclave_data = sbi_scratch_offset_ptr(scratch,
						       ipi_destroy_enclave_data_offset);

		ipi_destroy_enclave_sync = sbi_scratch_offset_ptr(scratch,
						       ipi_destroy_enclave_sync_offset);

		*ipi_destroy_enclave_sync = 0;

		ret = sbi_ipi_event_create(&ipi_destroy_enclave_ops);
		if (ret < 0) {
			sbi_bug("M mode: sbi_ipi_destroy_enclave_init: init5\n");
			sbi_scratch_free_offset(ipi_destroy_enclave_data_offset);
			return ret;
		}
		ipi_destroy_enclave_event = ret;
	} else {
	}
	return 0;
}