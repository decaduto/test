/*
	Made by Edoardo Mantovani,
		Plugin Handler for BlackFi.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

#include <sys/auxv.h>

#include <sys/mman.h>

#if UINTPTR_MAX == 0xffffffff
        #define ELF(iterator)  Elf32_##iterator
	#define ELF_FILE	EM_ARM
#elif UINTPTR_MAX == 0xffffffffffffffff
        #define ELF(iterator)  Elf64_##iterator
	#define ELF_FILE	EM_AARCH64
#endif


#define IMPORT_BIN(sect, file, sym) asm (\
    ".section " #sect "\n"                  /* Change section */\
    ".balign 4\n"                           /* Word alignment */\
    ".global " #sym "\n"                    /* Export the object address */\
    #sym ":\n"                              /* Define the object label */\
    ".incbin \"" file "\"\n"                /* Import the file */\
    ".global _sizeof_" #sym "\n"            /* Export the object size */\
    ".set _sizeof_" #sym ", . - " #sym "\n" /* Define the object size */\
    ".balign 4\n"                           /* Word alignment */\
    ".section \".text\"\n")                 /* Restore section */


IMPORT_BIN(".plugins", "rtl", rtl);

int main(int argc, char *argv[], char *envp[]){
	unsigned short p_n = 0;
	ELF(Phdr)      *p  = NULL;
	ELF(auxv_t)    *a = NULL;
	while(*envp++ != NULL);
	for(a = (ELF(auxv_t) *)envp; a->a_type != AT_NULL; a++){
		switch( a->a_type ){
			case AT_PHNUM:
				p_n = (unsigned short)(a->a_un.a_val);
			break;
			case AT_PHDR:
				p   = (ELF(Phdr) *)a->a_un.a_val;
			break;
		}
	}
	for(short j = 0; j < p_n; j++){
		if( p[j].p
	}
	return 0;
}

