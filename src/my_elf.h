#ifndef ELF_H
#define ELF_H

#include <elf.h>
#include <stdlib.h>

unsigned char *elf_load(const char *path);
int elf_sanity_check(const Elf64_Ehdr *hd);
void elf_header_dump(const Elf64_Ehdr *hd);
void elf_program_header_dump(const Elf64_Phdr *ph, size_t n);

#endif
