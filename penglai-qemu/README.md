# Modified qemu to support sPMP 

## sPMP implementation

### Register

- **cpu_bits.h**
  - [x] csr_spmpcfg0--3	    **0x1a0--0x1a3**
  - [x] csr_spmpaddr0--15    **0x1b0--0x1bf**
  - [x] csr_spmpexcp        **0x145**


### Data structure

- **cpu.h**
  - [x] MAX_RISCV_SPMPS
  - [x] spmp_state
- **pmp.h**
  - [x] date structures for spmp_table_t

### Enable sPMP

- **cpu.h**
  - [x] add RISCV_FEATURE_SPMP
  - [x] add cpu->cfg.spmp
- **cpu.c**
  - [x] set_feature(env, RISCV_FEATURE_SPMP)
  - [x] set cpu -> cfg.spmp
  - [x] add riscv_cpu_properties -> spmp
- **cpu_helper.c**
  - [x] check riscv_feature && spmp_hart_has_privs
    - get physical addr
    - tlb fill
  - [x] add spmp_violation
- **csr.c**
  - [x] csr function table
  - [x] define spmp_csr access priv to spmp

### Main logic

- **csr.c**
  - [x] read\write_spmp_cfg
  - [x] read\write_spmp_addr

- **pmp.c**
  - [x] Everything except pmp_get_a_field and pmp_decode_napot

## Test

### sPMP Test case

- sPMP read/write

  - [x] set region0 
    - cfg0 = 0b00001111 -> 0x0f
    - spmpaddr0 = 0x2200000000
    - try to read the spmpcfg and spmpaddr

- sPMP L-bit test

  - [x] test write ignore
    - cfg0 = 0b10011101 -> 0x9d
    - spmpaddr = 0x208ccdff
    - re-write spmpcfg and spmpaddr
    - write should be ignored

  - [x] test access without proper permission
    - cfg0 = 0b11011101 -> 0xdd
    - access paddr = 0x82333000
    - kernel should panic

- SMAP

  - [x] access region0 with U-bit set
    - cfg0 = 0b01011111 -> 0x5f
    - spmpaddr0 = 0x208ccdff
    - set SUM in sstatus to 1
    - access 0x82333000 in region0 shall succeed
    - set SUM in sstatus to 0
    - attempt to access 0x82333000 in region0
    - kernel should panic

- SMEP

  - [x] excute code in region0 with U-bit set
    - inject code in paddr 0x82333000
      - 0xe900893 (li a7, 233)
      - little-endian -> 0x9308900e
    - cfg0 = 0b01011111 -> 0x5f
    - spmpaddr0 = 0x208ccdff
    - attempt to execute code at 0x82333000
    - kernel should panic

