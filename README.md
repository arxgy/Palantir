# Penglai-TVM-Privileged
This repository provides the __Implementation__ and __Evaluation__ part of <span style="font-variant:small-caps;">Palantír</span> framework.

Penglai-Enclave is a scalable enclave system for RISC-V architecture.
You can find more details in its online document: [Penglai-doc](https://penglai-doc.readthedocs.io/en/latest/)

## Quick Start

Penglai uses Docker for building and uses submodules to track different components.

Therefore, the only requirement to build and run penglai-demo is:

- [Docker](https://docs.docker.com): for building/running Penglai
- Git: for downloading the code

The version for FPGA and RISC-V board is coming soon.

### Building

First, download the all the code:

`git clone https://github.com/Penglai-Enclave/Penglai-Enclave-TVM.git`

Enter the penglai-enclave directory, `cd penglai-enclave

And then,

`git submodule update --init --recursive`

Last, build penglai using our Docker image:

`./docker_cmd.sh build`

When the building process finished, you are ready to run the penglai demo.

## Running

In the penglai-enclave directory,

`./docker_cmd.sh qemu`

If everything is fine, you will enter a Linux terminal booted by Qemu with Penglai-installed.

Enter the terminal with the user name: root, and passwords: penglai.

**Insmod the enclave-driver**

`sh install.sh`

Any instruction below should be executed after you have booted your Penglai-TVM enclave platform, `./docker_cmd.sh qemu` is recommended.
For more details please refer to our code.

### Evaluation 1. Computational Overhead

In this section we evaluate Palantír's overhead by perform RV8 Benchmark Suite onto our Children Enclaves(CE).

- Native Linux 
    
    Just run rv8 on your Linux host machine.
- Penglai-TVM
  ```
  ./host-measure casename
  ```
- Palantír

  Change the `elf_file_name` inside `Penglai-sdk-TVM/demo/eval-1-benchmark/rv8-pe/rv8-pe.c` to `root/$(casename)` for any `casename` in RV8 suite. Then run
  ```
  ./host rv8-pe
  ```


### Evaluation 2. Interface

The `load-enclave` is a special program whose binary size can be controlled by macro `SIZE` inside.
So we dynamically adjust `SIZE` to evaluate time cost of `CREATE` and `ATTEST` in Penglai-TVM and Palantír.

- Penglai-TVM  

  ```
  ./host-interface load-enclave
  ```
- Palantír

  ```
  ./pe-interface load-enclave
  ```
 
### Evaluation 3. Case Studies

#### Memory Sharing
```
./host case-inspector
```

In this case, `case-inspector`, the Privileged Enclave (PE),  will launch `case-inspectee` and perform introspection onto it.

#### Live Enclave Introspection
```
./host case-share
```

In this case, `case-share`, the PE, will launch `case-sharer`, `case-sharee`, `case-sharee-plus` and plays as a scheduler.
During execution, `case-sharer` will share a chunk of its virtual address space to PE and other peer CE.
Then `case-sharee`, `case-sharee-plus` will require `case-sharer`'s page respectively, thus ensuring memory sharing.

#### Live Enclave Migration
```
./host case-migraor
```

In this case, we perform a enclave migration locally.
First, `case-migrator`, the PE, will `DESTROY` its children enclave `case-migratee`.
Then `case-migrator` re-create `case-migratee` from its stored runtime state and resume to execution.

The state encrytion, file generation, and socket support are orthogonal to our work.
Since Penglai-TVM does not support socket, we leave remote enclave migration to future. 



## License Details

Mulan Permissive Software License，Version 1 (Mulan PSL v1)


## Code Contributions

If you are developing Penglai, please use pull requests on **target submodule project** (not on the super project).

Please feel free to post your concerns, ideas, code or anything others to issues.

## Collaborators

__Implementation__: Anonymous Author.

__Evaluation__: Anonymous Author, Anonymous Author.


