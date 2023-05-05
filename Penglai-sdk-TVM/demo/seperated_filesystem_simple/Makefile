all:
	make -C ramdisk
	make -C file
	make -C file-defer
	make -C persistency_driver
	#make -C bio
	rm decouplefs_simple -rf
	mkdir decouplefs_simple
	cp ramdisk/ramdisk decouplefs_simple
	#cp bio/bio  transfer
	cp file/filesystem decouplefs_simple
	cp file-defer/filesystem-defer decouplefs_simple
	cp persistency_driver/persistency decouplefs_simple
clean:
	make -C ramdisk clean
	make -C file clean
	make -C file-defer clean
	make -C persistency_dr clean
	#make -C bio clean
	rm -rf decouplefs_simple

