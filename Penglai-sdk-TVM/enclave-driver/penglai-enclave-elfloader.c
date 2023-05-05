#include "penglai-enclave-elfloader.h"
#include "penglai-enclave-driver.h"

int penglai_enclave_load_NOBITS_section(enclave_mem_t* enclave_mem, void * elf_sect_addr, int elf_sect_size)
{
  vaddr_t addr, enclave_new_page;

  int size;
  for(addr = (vaddr_t)elf_sect_addr; addr < (vaddr_t)elf_sect_addr + elf_sect_size; addr += RISCV_PGSIZE)
  {   
    enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
    if (addr + RISCV_PGSIZE >(vaddr_t) elf_sect_addr + elf_sect_size)
      size = elf_sect_size % RISCV_PGSIZE;
    else
      size = RISCV_PGSIZE;
    memset((void *) enclave_new_page, 0, size);
  }
  return 0;
}

/**
 * \param elf_prog_infile_addr The content in elf file.
 * \param elf_prog_addr The virtual addr for program begin addr.
 * \param elf_prog_size The size of prog segment.
 * \param type The enclave type.
 * \param flags The page flags(attribution).
 */
int penglai_enclave_load_program(enclave_mem_t* enclave_mem, vaddr_t elf_prog_infile_addr, void * elf_prog_addr, int elf_prog_size, enclave_type_t type, int flags)
{
  vaddr_t addr, enclave_new_page;
  int size, r;
  for(addr =  (vaddr_t)elf_prog_addr; addr <  (vaddr_t)elf_prog_addr + elf_prog_size; addr += RISCV_PGSIZE)
  {   
    if((flags & PF_W) == 2)
      enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
    else
      enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_ROPAGE);

    if(addr + RISCV_PGSIZE > (vaddr_t)elf_prog_addr + elf_prog_size)
      size = elf_prog_size % RISCV_PGSIZE;
    else
      size = RISCV_PGSIZE;

    r = copy_from_user((void* )enclave_new_page, (void *)(elf_prog_infile_addr + addr - (vaddr_t)elf_prog_addr), size);
  }
  return 0;
}

int penglai_enclave_loadelf(enclave_mem_t*enclave_mem, void* __user elf_ptr, unsigned long size, vaddr_t * elf_entry_point, enclave_type_t type)
{
  struct elfhdr elf_hdr;
  struct elf_phdr elf_prog_hdr;
  struct elf_shdr elf_sect_hdr;
  int i,  elf_prog_size;
  vaddr_t elf_sect_ptr, elf_prog_ptr, elf_prog_addr, elf_prog_infile_addr, elf_prog_flags;

  if(copy_from_user(&elf_hdr, elf_ptr, sizeof(struct elfhdr)) != 0)
  {
    penglai_eprintf("penglai_enclave_loadelf: elf_hdr copy_from_user failed\n");
    return -1;
  }

  *elf_entry_point = elf_hdr.e_entry;
  elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;

  /* Load NOBITS section */
  for (i = 0; i < elf_hdr.e_shnum;i++)
  {
    if (copy_from_user(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(struct elf_shdr)))
    {
      penglai_eprintf("penglai_enclave_loadelf: elf_sect_hdr copy_from_user failed\n");
      elf_sect_ptr += sizeof(struct elf_shdr);
      return -1;
    }
    if (elf_sect_hdr.sh_addr == 0)
    {
      elf_sect_ptr += sizeof(struct elf_shdr);
      continue;
    }

    // Ignore the other sections except the NOBITS
    if (elf_sect_hdr.sh_type == SHT_NOBITS)
    {
      vaddr_t elf_sect_addr = elf_sect_hdr.sh_addr;
      int elf_sect_size = elf_sect_hdr.sh_size;
      if (penglai_enclave_load_NOBITS_section(enclave_mem,(void *)elf_sect_addr,elf_sect_size) < 0)
      {
        penglai_eprintf("penglai_enclave_loadelf: penglai enclave load NOBITS section failed\n");
        return -1;
      }
    }

    elf_sect_ptr += sizeof(struct elf_shdr);
  }

  // Load PROGBITS segment
  elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;
   
  for(i = 0; i < elf_hdr.e_phnum;i++)
  {         
    if (copy_from_user(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(struct elf_phdr)))
    {
      penglai_eprintf("penglai_enclave_loadelf: elf_prog_hdr copy_from_user failed\n");
      elf_prog_ptr += sizeof(struct elf_phdr);
      return -1;
    }

    elf_prog_addr = elf_prog_hdr.p_vaddr;
    elf_prog_size = elf_prog_hdr.p_filesz;
    elf_prog_flags = elf_prog_hdr.p_flags;
    elf_prog_infile_addr = (vaddr_t) elf_ptr + elf_prog_hdr.p_offset;
    if(penglai_enclave_load_program(enclave_mem, elf_prog_infile_addr, (void *)elf_prog_addr, elf_prog_size, type, elf_prog_flags) < 0)
    {
      penglai_eprintf("penglai_enclave_loadelf: penglai enclave load program failed\n");
      return -1;
    }
    elf_prog_ptr += sizeof(struct elf_phdr);
  }
  return 0;
} 

/**
 * \brief Calculate the total memory size for enclave elf file.
 */
int penglai_enclave_elfmemsize(void* __user elf_ptr,   int* size)
{
  struct elfhdr elf_hdr;
  struct elf_phdr elf_prog_hdr;
  struct elf_shdr elf_sect_hdr;
  int i,  elf_prog_size;
  vaddr_t elf_sect_ptr, elf_prog_ptr;
  if(copy_from_user(&elf_hdr, elf_ptr, sizeof(struct elfhdr)) != 0)
  {
    penglai_eprintf("penglai_enclave_elfmemsize: elf_hdr copy_from_user failed\n");
    return -1;
  }
  elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;

  for (i = 0; i < elf_hdr.e_shnum;i++)
  {
    if (copy_from_user(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(struct elf_shdr)))
    {
      penglai_eprintf("penglai_enclave_elfmemsize: elf_sect_hdr copy_from_user failed\n");
      elf_sect_ptr += sizeof(struct elf_shdr);
      return -1;
    }
    if (elf_sect_hdr.sh_addr == 0)
    {
      elf_sect_ptr += sizeof(struct elf_shdr);
      continue;
    }

    // Calculate the size of the NOBITS section
    if (elf_sect_hdr.sh_type == SHT_NOBITS)
    {
      int elf_sect_size = elf_sect_hdr.sh_size;
      *size = *size + elf_sect_size;
    }
    elf_sect_ptr += sizeof(struct elf_shdr);
  }

  // Calculate the size of the PROGBITS segment
  elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;
   
  for(i = 0; i < elf_hdr.e_phnum;i++)
  {         
    if (copy_from_user(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(struct elf_phdr)))
    {
      penglai_eprintf("penglai_enclave_elfmemsize: elf_prog_hdr copy_from_user failed\n");
      elf_prog_ptr += sizeof(struct elf_phdr);
      return -1;
    }

    // Virtual addr for program begin address
    elf_prog_size = elf_prog_hdr.p_filesz;
    *size = *size + elf_prog_size;
    elf_prog_ptr += sizeof(struct elf_phdr);
  }
  return 0;
} 

int penglai_enclave_eapp_loading(enclave_mem_t* enclave_mem,  void* __user elf_ptr, unsigned long size, vaddr_t * elf_entry_point, vaddr_t stack_ptr, int stack_size, enclave_type_t type)
{
  vaddr_t addr;

  // Initialize the stack
  for(addr = stack_ptr - stack_size; addr < stack_ptr; addr += RISCV_PGSIZE)
  {
    enclave_alloc_page(enclave_mem, addr, ENCLAVE_STACK_PAGE);
  }

  // Load the enclave code
  if(penglai_enclave_loadelf(enclave_mem, elf_ptr, size, elf_entry_point, type) < 0)
  {
    penglai_eprintf("penglai_enclave_eapp_loading: penglai enclave loadelf failed\n");
    return -1;
  }

  return 0;
}
