# Penglai SDK

This is the SDK of Penglai TEE solution.

This file will list the demos and tutorials of the SDK.

## Quick Start

Please build Penglai SDK with commands in the penglai-enclave top project.

## Tutorials


## Demos

### LittleFS

LittleFS is built as an enclave server which can provide file system service to other enclaves.

The code is in demo/littlefs.

To test the littlefs, after boot penglai:

	insmod penglai.ko
	./fshost testfs lfs

You should see results like:

	lfs mount succeed
	after fwrite
	fopen /create.txt for read
	...

## Licenses

Mulan Permissive Software License，Version 1 (Mulan PSL v1)

## Code Contributions

Please use Merge Request/Pull Requests on to pose and contribute your work.

Please fell free to post your concerns, ideas, code or anything others to issues.

## Wiki

Please refer the wiki for more details
