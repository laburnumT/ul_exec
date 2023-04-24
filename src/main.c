#include <alloca.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "definitions.h"
#include "helper.h"
#include "my_elf.h"

NORETURN void jump(void *entry_point, void *stack_pointer)
{
        asm volatile("mov $0, %%rbp\n"
                     "mov %[sp], %%rsp\n"
                     "mov %[fin], %%rdx\n"
                     "jmp *%[ep]" ::[fin] "r"(NULL),
                     [sp] "r"(stack_pointer), [ep] "r"(entry_point)
                     : "rdx");

        unreachable();
}

static unsigned char *map_exec(const unsigned char *const addr)
{
        const Elf64_Ehdr *const elf_header = (Elf64_Ehdr *)addr;
        const Elf64_Phdr *const program_headers =
            (Elf64_Phdr *)(addr + elf_header->e_phoff);

        size_t exec_size = 0;

        for (size_t i = 0; i < elf_header->e_phnum; ++i) {
                if ((program_headers + i)->p_type != PT_LOAD)
                        continue;
                if ((program_headers + i)->p_vaddr +
                        (program_headers + i)->p_memsz >
                    exec_size)
                        exec_size = (program_headers + i)->p_vaddr +
                                    (program_headers + i)->p_memsz;
        }

        unsigned char *const exec =
            mmap(NULL, exec_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (exec == MAP_FAILED) // NOLINT
                exit_with_error();
        memset(exec, 0, exec_size);

        for (size_t i = 0; i < elf_header->e_phnum; ++i) {
                if ((program_headers + i)->p_type != PT_LOAD)
                        continue;

                memmove(exec + (program_headers + i)->p_vaddr,
                        addr + (program_headers + i)->p_offset,
                        (program_headers + i)->p_filesz);

                const uintptr_t offset =
                    (uintptr_t)(exec + (program_headers + i)->p_vaddr) %
                    sysconf(_SC_PAGE_SIZE);

                int flags = 0;

                if ((program_headers + i)->p_flags & PF_R)
                        flags |= PROT_READ;
                if ((program_headers + i)->p_flags & PF_W)
                        flags |= PROT_WRITE;
                if ((program_headers + i)->p_flags & PF_X)
                        flags |= PROT_EXEC;

                if (mprotect(exec + (program_headers + i)->p_offset - offset,
                             (program_headers + i)->p_filesz + offset,
                             flags) == -1)
                        exit_with_error();
        }
        return exec;
}

static char *check_linker(const unsigned char *const addr)
{
        const Elf64_Ehdr *const elf_header = (Elf64_Ehdr *)addr;
        const Elf64_Phdr *const program_headers =
            (Elf64_Phdr *)(addr + elf_header->e_phoff);
        for (size_t i = 0; i < elf_header->e_phnum; ++i) {
                if ((program_headers + i)->p_type == PT_INTERP)
                        return (char *)(addr + (program_headers + i)->p_offset);
        }
        return NULL;
}

static void *ul_exec(const char *const path, char *const *argv)
{
        size_t argc            = 0;
        char *const *copy_argv = argv;
        for (; *copy_argv; ++copy_argv, ++argc)
                ;
        char *const *envp      = copy_argv + 1;
        char *const *copy_envp = envp;
        for (; *copy_envp; ++copy_envp)
                ;
        Elf64_auxv_t *auxv = (Elf64_auxv_t *)(copy_envp + 1);

        unsigned char *entry_point         = NULL;
        const unsigned char *const addr    = elf_load(path);
        const Elf64_Ehdr *const elf_header = (Elf64_Ehdr *)addr;
        unsigned char *const exec          = map_exec(addr);

        const char *const linker   = check_linker(addr);
        unsigned char *linker_exec = NULL;
        if (linker) {
                const unsigned char *const addr = elf_load(linker);
                linker_exec                     = map_exec(addr);
                Elf64_Ehdr *linker_header       = (Elf64_Ehdr *)addr;
                entry_point = linker_exec + linker_header->e_entry;
        } else {
                entry_point = exec + elf_header->e_entry;
        }

        const size_t stack_size = 512;

        uintptr_t *const stack = alloca(stack_size * sizeof(uintptr_t));
        memset(stack, 0, stack_size * sizeof(uintptr_t));
        size_t front = 0;
        size_t back  = stack_size - 1;

        *(stack + back--)  = (uintptr_t)NULL;
        *(stack + front++) = argc;

        char *strings = (char *)(stack + back);
        for (; *argv; ++argv) {
                size_t len = strlen(*argv);
                strings -= len + 1;
                strcpy(strings, *argv);
                *(stack + front++) = (uintptr_t)strings;
        }
        *(stack + front++) = (uintptr_t)NULL;
        for (; *envp; ++envp) {
                size_t len = strlen(*envp);
                strings -= len + 1;
                strcpy(strings, *envp);
                *(stack + front++) = (uintptr_t)strings;
        }
        *(stack + front++) = (uintptr_t)NULL;
        for (; auxv->a_type != AT_NULL; ++auxv) {
                switch (auxv->a_type) {
                case AT_BASE:
                        if (linker)
                                auxv->a_un.a_val = (uintptr_t)entry_point;
                        break;
                case AT_PHDR:
                        auxv->a_un.a_val =
                            (uintptr_t)(exec + elf_header->e_phoff);
                        break;
                case AT_PHNUM:
                        auxv->a_un.a_val = elf_header->e_phnum;
                        break;
                case AT_ENTRY:
                        auxv->a_un.a_val =
                            (uintptr_t)(exec + elf_header->e_entry);
                        break;
                }
                *(stack + front++) = auxv->a_type;
                *(stack + front++) = auxv->a_un.a_val;
        }
        *(stack + front++) = (uintptr_t)NULL;

        jump(entry_point, stack);

        return NULL;
}

int main(int argc, char **argv)
{
        ++argv;
        ul_exec(*argv, argv);

        return 0;
}
