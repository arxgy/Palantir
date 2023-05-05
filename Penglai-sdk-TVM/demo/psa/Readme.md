# PSA storage interface support in the Penglai enclave
### Overview:
We have intergrated psa storage server in the Penglai enclave as a server enclave, which provide psa storage interface for caller enclave.
Currently, it support following five api:
+ psa_ps_set(psa_storage_uid_t uid, size_t data_length, const void *p_data, psa_storage_create_flags_t create_flags)
+ psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size, void *p_data, size_t *p_data_length)
+ psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
+ psa_status_t psa_ps_remove(psa_storage_uid_t uid)
+ uint32_t psa_ps_get_support(void)

Psa server enclave provides highest security guarantee for object storage, all the objects stored in the external storage can obtain the encryption, integrity and rollback protection. We using AES-GCM algorithm to encrypt and authenticate the object data, and store the object version in the object table. Also we should encrypt and authenticate (like using MAC) the object table and the version of object table should be reserved in the non-volatile storage (haven't implemented in the current code).

### How to use the psa server and invoke the psa storage API?
We integrate the psa server call stub and callee stub in the enclave library and psa server. When caller enclave want to invoke the psa sevice, it need include the "psa/protected_storage.h", which declare all psa storage interface. The calling procedure will then plunge into the call stub, all the arguments will be marshalling and stored in the communicating memory. The underlying ipc mechanism will transfer the memory to the callee stub in the psa server, and unmarshalling the argument and re-construct pointer and struct. Later the psa server will use this argument and tackle the request. Because all argument is marshalling between the transferring, so it do not care about the underlying ipc mechanism. The psa server enclave can re-construct the argument correctly even if there is no sharing memory with the caller enclave.

### A simple demo: fingerprint recognition
We implement a simple fingerprint recognition module in the penglai psa server. If fingerprint module wants to invoke the psa storage service, the developer need at least install three server enclave: fingerprint server, psa server and filesystem server (may be sperated into filesystem and persistency servers); also a client enclave and host. we can use the following script to run a simple fingerprint recognition program with psa interface:
`./fphost fp_client fp_server psa_server decouplefs_simple/filesystem decouplefs_simple/persistency`.
The host program is responsible for creating the client enclave and passing the fingerprint date. After fingerprint client enclave is created, it pass the fingerprint data, uid and request type to the fingerprint server. As for fingerprint server enclave, when a request is arrived, it parse the request type and client id from the caller argument, and invoke the corresponding psa server service/interface. After psa server disposing all requests, fingerprint server returns the final result to fingerprint client, and waits for the subsequent requests. 
Above is the workflow for a simple fringerprint recognition demo using the underlying ipc mechanism and psa server enclave. the data is transfer from the host, client, fingerprint server, psa server, filesystem server and persistency server. Each server enclave is isolated with each other and using the relay page to communicate (other ipc mechanism is also acceptable), also you can implement your own fingerprint processing logic in the fingerprint server (currently, we just match whether the given data and stored data is accordance).

### Other available interfaces / APIs / functionalities in Penglai enclave
Penglai infrasture provids primary libc interfaces (e.g., malloc, mmap, fputs, fgets,...), and cryptographic associated functions (e.g., symmetric cryptography function: AES, DES, asymmetric cryptography function: RAS, Hash and MAC function: HMAC) supported by musl libc and wolfssl library. Using these practical interfaces or APIs can realize mostly security-sensitive programs running in the Penglai enclave, which can gain the  highest security guarantee.

### Following function is not finish
1. In psa_crypto_interface.c: the key_origin should be the hardware-Unique key (resided in the rom or other persistent read-only storage), and all other keys are derived from it.
3. In psa_object_table.c: Now, psa server uses the MAGIC filename to store the object files and table file.
4. In psa_server.c: get_caller_client_id() get the caller eid as the client id, however the eid is changed if machine is reboot (meeting failure), So when enclave reboot, it can not get the previous object (because eid is changed).
5. In sst_object_def.h: SST_MAX_OBJECT_DATA_SIZE define the maximum object size (1000 in current config), and SST_NUM_ASSETS define the total files can be reserved in the psa_server.
6. In psa_object_table.c: Use the persistent storage to emulate the nvme. Replace the nvc read and write functions in a real nvm-enabled chip.
7. Currently, the psa seed in the monitor is fixed (SYS_GETRANDOM). Actually this seed needs to be generated by hardware

### Fixed:
2. In psa_object_server.c: sst_object_table_init() is not tested, because there is no persistent storage in the emulating environment.
6. In psa_object_table.c: nvc_1 is not finished, nvc should be stored in the non-volatile storage. Each time, when we update the object table, we should increase the nvc_1 to defend against roll-back attack. (Does not consider the roll back protection in psa_object_table)