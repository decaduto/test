#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <endian.h>
#include <stddef.h>
#include <stdarg.h>

#include <linux/types.h>
#include <linux/const.h>

#include <sys/stat.h>
#include <sys/mman.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
        #pragma message "using little endian!"
        #include <linux/byteorder/little_endian.h>
#else
        #pragma message "using big endian!"
        #include <linux/byteorder/big_endian.h>
#endif

#ifndef ALIGN
        #define ALIGN(x, a)     __ALIGN_KERNEL((x), (a))
#endif


#define RTL_VER_SIZE	32

__attribute__((packed)) struct fw_block {
	__le32 type;
	__le32 length;
};

__attribute__((packed)) struct fw_header {
	uint8_t checksum[32];
	char version[RTL_VER_SIZE];
	struct fw_block blocks[];
};

enum rtl_fw_type {
	RTL_FW_END = 0,
	RTL_FW_PLA,
	RTL_FW_USB,
	RTL_FW_PHY_START,
	RTL_FW_PHY_STOP,
	RTL_FW_PHY_NC,
	RTL_FW_PHY_FIXUP,
	RTL_FW_PHY_UNION_NC,
	RTL_FW_PHY_UNION_NC1,
	RTL_FW_PHY_UNION_NC2,
	RTL_FW_PHY_UNION_UC2,
	RTL_FW_PHY_UNION_UC,
	RTL_FW_PHY_UNION_MISC,
	RTL_FW_PHY_SPEED_UP,
	RTL_FW_PHY_VER,
};

int main(int argc, char *argv[]){
	unsigned char *f_name = argv[1];
	if( f_name != NULL ){
		printf("working on: %s\n", f_name);
	}else{
		printf("please, give some args to the cmdline!\n");
		exit(-1);
	}
	int fd = open(f_name, O_RDWR);
	struct stat *f_s = (struct stat *)malloc(sizeof(struct stat));
	fstat(fd, f_s);
	unsigned long f_len = f_s->st_size;
	printf("current size of the file is %lu \n", f_len);

	unsigned char *fw_in_mem = (unsigned char *)mmap(
							NULL,
							f_len,
							PROT_READ  | PROT_WRITE,
							MAP_SHARED | MAP_FILE,
							fd,
							0x00
							);

	struct fw_header *fw_hdr = (struct fw_header *)fw_in_mem;
	int timing_cnt = 0;
	for(int i = offsetof(struct fw_header, blocks); i < f_len;) {
		struct fw_block *block = (struct fw_block *)&fw_in_mem[i];
		switch (__le32_to_cpu(block->type)){
			case RTL_FW_END:
				printf("%d caught RTL_FW_END start: %d len: %d \n", timing_cnt, i, block->length);
				timing_cnt++;
			break;
			case RTL_FW_PLA:
				printf("%d caught RTL_FW_PLA start: %d len: %d \n", timing_cnt, i, block->length);
                                timing_cnt++;
			break;
			case RTL_FW_USB:
				printf("%d caught RTL_FW_USB start: %d len: %d \n", timing_cnt, i, block->length);
                                timing_cnt++;
			break;
			case RTL_FW_PHY_START:
				printf("%d caught RTL_FW_PHY_START len: %d \n", timing_cnt, block->length);
                                timing_cnt++;
			break;
			case RTL_FW_PHY_STOP:
				printf("%d caught RTL_FW_PHY_STOP len: %d \n", timing_cnt, block->length);
                                timing_cnt++;
			break;
			case RTL_FW_PHY_NC:
				printf("caught RTL_FW_pHY_NC\n");
			break;
			case RTL_FW_PHY_VER:
				printf("caught RTL_FW_PHY_VER\n");
			break;
			case RTL_FW_PHY_UNION_NC:
			case RTL_FW_PHY_UNION_NC1:
			case RTL_FW_PHY_UNION_NC2:
			case RTL_FW_PHY_UNION_UC2:
			case RTL_FW_PHY_UNION_UC:
			case RTL_FW_PHY_UNION_MISC:
				printf("caught FW_PHY_UNION\n");
			break;
			case RTL_FW_PHY_FIXUP:
				printf("caught RTL_FW_PHY_FIXUP\n");
			break;
			case RTL_FW_PHY_SPEED_UP:
				printf("%d caught RTL_FW_PHY_SPEED_UP start: %d len: %d \n", timing_cnt, i, block->length);
                                timing_cnt++;
			break;
		}
		i += ALIGN(__le32_to_cpu(block->length), 8);
	}
	munmap(fw_in_mem, f_len);
	close(fd);
	free(f_s);
	return 0;
}

