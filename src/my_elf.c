#include "my_elf.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "helper.h"

unsigned char *elf_load(const char *const path)
{
        FILE *const fp = fopen(path, "rb");
        if (!fp)
                exit_with_error();

        struct stat file_info;
        if (fstat(fileno(fp), &file_info) == -1)
                exit_with_error();

        unsigned char *const addr =
            mmap(NULL, file_info.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE,
                 fileno(fp), 0);

        if (addr == MAP_FAILED) // NOLINT
                exit_with_error();

        if (fclose(fp))
                exit_with_error();

        Elf64_Ehdr *elf_header = (Elf64_Ehdr *)addr;

        elf_sanity_check(elf_header);

        return addr;
}

int elf_sanity_check(const Elf64_Ehdr *const hd)
{
        if (memcmp(hd->e_ident, ELFMAG, SELFMAG) != 0) {
                (void)fputs("Not a valid ELF file\n", stderr);
                exit(EXIT_FAILURE);
        }
        if (*(hd->e_ident + EI_CLASS) != ELFCLASS64) {
                (void)fputs("Only accepting 64 bit ELF files", stderr);
                exit(EXIT_FAILURE);
        }
        switch (*(hd->e_ident + EI_DATA)) {
        case ELFDATA2LSB:
        case ELFDATA2MSB:
                break;
        default:
                (void)fputs("Invalid encoding", stderr);
                exit(EXIT_FAILURE);
        }
        if (*(hd->e_ident + EI_VERSION) != EV_CURRENT) {
                (void)fputs("Invalid ELF version", stderr);
                exit(EXIT_FAILURE);
        }
        switch (*(hd->e_ident + EI_OSABI)) {
        case ELFOSABI_GNU:
        case ELFOSABI_SYSV:
                break;
        case ELFOSABI_HPUX:
        case ELFOSABI_NETBSD:
        case ELFOSABI_SOLARIS:
        case ELFOSABI_AIX:
        case ELFOSABI_IRIX:
        case ELFOSABI_FREEBSD:
        case ELFOSABI_TRU64:
        case ELFOSABI_MODESTO:
        case ELFOSABI_OPENBSD:
        case ELFOSABI_ARM_AEABI:
        case ELFOSABI_ARM:
        case ELFOSABI_STANDALONE:
        default:
                (void)fputs("Invalid ABI", stderr);
                exit(EXIT_FAILURE);
        }
        if (*(hd->e_ident + EI_ABIVERSION) != 0) {
                (void)fputs("Invalid ABI", stderr);
                exit(EXIT_FAILURE);
        }
        if (*(hd->e_ident + EI_PAD) != 0) {
                (void)fputs("Likely out of date scanner", stderr);
                exit(EXIT_FAILURE);
        }

        switch (hd->e_type) {
        case ET_EXEC:
        case ET_DYN:
                break;
        case ET_REL:
        case ET_CORE:
                (void)fputs("Not dealing with REL or CORE ELF files\n", stderr);
                exit(EXIT_FAILURE);
        default:
                (void)fputs("Unkown ELF type", stderr);
                exit(EXIT_FAILURE);
        }

        if (hd->e_machine != EM_X86_64) {
                (void)fputs("Only accepting x64 elf files", stderr);
                exit(EXIT_FAILURE);
        }

        return 0;
}

void elf_header_dump(const Elf64_Ehdr *const hd)
{
        printf("Magic:");
        for (size_t i = 0; i < EI_NIDENT; ++i)
                printf(" %x", *(hd->e_ident + i));
        puts("");

        printf("Class: ");
        switch (*(hd->e_ident + EI_CLASS)) {
        case ELFCLASS64:
                puts("64-bit");
                break;
        case ELFCLASS32:
                puts("32-bit");
                break;
        default:
                puts("Unknown class");
        }

        printf("Data: ");
        switch (*(hd->e_ident + EI_DATA)) {
        case ELFDATA2LSB:
                puts("2's complement little endian");
                break;
        case ELFDATA2MSB:
                puts("2's complement big endian");
                break;
        default:
                puts("Unknown encoding");
        }

        printf("Version: ");
        switch (*(hd->e_ident + EI_VERSION)) {
        case EV_CURRENT:
                puts("current");
                break;
        default:
                puts("Unkown version");
        }

        printf("OS/ABI: ");
        switch (*(hd->e_ident + EI_OSABI)) {
        case ELFOSABI_SYSV:
                puts("UNIX System V ABI");
                break;
        case ELFOSABI_HPUX:
                puts("HP-UX");
                break;
        case ELFOSABI_NETBSD:
                puts("NetBSD");
                break;
        case ELFOSABI_GNU:
                puts("Object uses GNU ELF extensions");
                break;
        case ELFOSABI_SOLARIS:
                puts("Sun Solaris");
                break;
        case ELFOSABI_AIX:
                puts("IBM AIX");
                break;
        case ELFOSABI_IRIX:
                puts("SGI Irix");
                break;
        case ELFOSABI_FREEBSD:
                puts("FreeBSD");
                break;
        case ELFOSABI_TRU64:
                puts("Compaq TRU64 UNIX");
                break;
        case ELFOSABI_MODESTO:
                puts("Novell Modesto");
                break;
        case ELFOSABI_OPENBSD:
                puts("OpenBSD");
                break;
        case ELFOSABI_ARM_AEABI:
                puts("ARM EABI");
                break;
        case ELFOSABI_ARM:
                puts("ARM");
                break;
        case ELFOSABI_STANDALONE:
                puts("Standalone (embedded) application");
                break;
        default:
                (void)fputs("Invalid ABI", stderr);
                exit(EXIT_FAILURE);
        }

        printf("Type: ");
        switch (hd->e_type) {
        case ET_REL:
                puts("REL (Relocatable file)");
                break;
        case ET_EXEC:
                puts("EXEC (Executable file)");
                break;
        case ET_DYN:
                puts("DYN (Shared object file)");
                break;
        case ET_CORE:
                puts("CORE (Core file)");
                break;
        default:
                puts("Unkown ELF type");
        }

        printf("Machine: ");
        switch (hd->e_machine) {
        case EM_NONE:
                puts("No machine");
                break;
        case EM_M32:
                puts("AT&T WE 32100");
                break;
        case EM_SPARC:
                puts("SUN SPARC");
                break;
        case EM_386:
                puts("Intel 80386");
                break;
        case EM_68K:
                puts("Motorola m68k family");
                break;
        case EM_88K:
                puts("Motorola m88k family");
                break;
        case EM_IAMCU:
                puts("Intel MCU");
                break;
        case EM_860:
                puts("Intel 80860");
                break;
        case EM_MIPS:
                puts("MIPS R3000 big-endian");
                break;
        case EM_S370:
                puts("IBM System/370");
                break;
        case EM_MIPS_RS3_LE:
                puts("MIPS R3000 little-endian");
                break;
        case EM_PARISC:
                puts("HPPA");
                break;
        case EM_VPP500:
                puts("Fujitsu VPP500");
                break;
        case EM_SPARC32PLUS:
                puts("Sun's v8plus");
                break;
        case EM_960:
                puts("Intel 80960");
                break;
        case EM_PPC:
                puts("PowerPC");
                break;
        case EM_PPC64:
                puts("PowerPC 64-bit");
                break;
        case EM_S390:
                puts("IBM S390");
                break;
        case EM_SPU:
                puts("IBM SPU/SPC");
                break;
        case EM_V800:
                puts("NEC V800 series");
                break;
        case EM_FR20:
                puts("Fujitsu FR20");
                break;
        case EM_RH32:
                puts("TRW RH-32");
                break;
        case EM_RCE:
                puts("Motorola RCE");
                break;
        case EM_ARM:
                puts("ARM");
                break;
        case EM_FAKE_ALPHA:
                puts("Digital Alpha");
                break;
        case EM_SH:
                puts("Hitachi SH");
                break;
        case EM_SPARCV9:
                puts("SPARC v9 64-bit");
                break;
        case EM_TRICORE:
                puts("Siemens Tricore");
                break;
        case EM_ARC:
                puts("Argonaut RISC Core");
                break;
        case EM_H8_300:
                puts("Hitachi H8/300");
                break;
        case EM_H8_300H:
                puts("Hitachi H8/300H");
                break;
        case EM_H8S:
                puts("Hitachi H8S");
                break;
        case EM_H8_500:
                puts("Hitachi H8/500");
                break;
        case EM_IA_64:
                puts("Intel Merced");
                break;
        case EM_MIPS_X:
                puts("Stanford MIPS-X");
                break;
        case EM_COLDFIRE:
                puts("Motorola Coldfire");
                break;
        case EM_68HC12:
                puts("Motorola M68HC12");
                break;
        case EM_MMA:
                puts("Fujitsu MMA Multimedia Accelerator");
                break;
        case EM_PCP:
                puts("Siemens PCP");
                break;
        case EM_NCPU:
                puts("Sony nCPU embeeded RISC");
                break;
        case EM_NDR1:
                puts("Denso NDR1 microprocessor");
                break;
        case EM_STARCORE:
                puts("Motorola Start*Core processor");
                break;
        case EM_ME16:
                puts("Toyota ME16 processor");
                break;
        case EM_ST100:
                puts("STMicroelectronic ST100 processor");
                break;
        case EM_TINYJ:
                puts("Advanced Logic Corp. Tinyj emb.fam");
                break;
        case EM_X86_64:
                puts("AMD x86-64 architecture");
                break;
        case EM_PDSP:
                puts("Sony DSP Processor");
                break;
        case EM_PDP10:
                puts("Digital PDP-10");
                break;
        case EM_PDP11:
                puts("Digital PDP-11");
                break;
        case EM_FX66:
                puts("Siemens FX66 microcontroller");
                break;
        case EM_ST9PLUS:
                puts("STMicroelectronics ST9+ 8/16 mc");
                break;
        case EM_ST7:
                puts("STmicroelectronics ST7 8 bit mc");
                break;
        case EM_68HC16:
                puts("Motorola MC68HC16 microcontroller");
                break;
        case EM_68HC11:
                puts("Motorola MC68HC11 microcontroller");
                break;
        case EM_68HC08:
                puts("Motorola MC68HC08 microcontroller");
                break;
        case EM_68HC05:
                puts("Motorola MC68HC05 microcontroller");
                break;
        case EM_SVX:
                puts("Silicon Graphics SVx");
                break;
        case EM_ST19:
                puts("STMicroelectronics ST19 8 bit mc");
                break;
        case EM_VAX:
                puts("Digital VAX");
                break;
        case EM_CRIS:
                puts("Axis Communications 32-bit emb.proc");
                break;
        case EM_JAVELIN:
                puts("Infineon Technologies 32-bit emb.proc");
                break;
        case EM_FIREPATH:
                puts("Element 14 64-bit DSP Processor");
                break;
        case EM_ZSP:
                puts("LSI Logic 16-bit DSP Processor");
                break;
        case EM_MMIX:
                puts("Donald Knuth's educational 64-bit proc");
                break;
        case EM_HUANY:
                puts("Harvard University machine-independent object files");
                break;
        case EM_PRISM:
                puts("SiTera Prism");
                break;
        case EM_AVR:
                puts("Atmel AVR 8-bit microcontroller");
                break;
        case EM_FR30:
                puts("Fujitsu FR30");
                break;
        case EM_D10V:
                puts("Mitsubishi D10V");
                break;
        case EM_D30V:
                puts("Mitsubishi D30V");
                break;
        case EM_V850:
                puts("NEC v850");
                break;
        case EM_M32R:
                puts("Mitsubishi M32R");
                break;
        case EM_MN10300:
                puts("Matsushita MN10300");
                break;
        case EM_MN10200:
                puts("Matsushita MN10200");
                break;
        case EM_PJ:
                puts("picoJava");
                break;
        case EM_OPENRISC:
                puts("OpenRISC 32-bit embedded processor");
                break;
        case EM_ARC_COMPACT:
                puts("ARC International ARCompact");
                break;
        case EM_XTENSA:
                puts("Tensilica Xtensa Architecture");
                break;
        case EM_VIDEOCORE:
                puts("Alphamosaic VideoCore");
                break;
        case EM_TMM_GPP:
                puts("Thompson Multimedia General Purpose Proc");
                break;
        case EM_NS32K:
                puts("National Semi. 32000");
                break;
        case EM_TPC:
                puts("Tenor Network TPC");
                break;
        case EM_SNP1K:
                puts("Trebia SNP 1000");
                break;
        case EM_ST200:
                puts("STMicroelectronics ST200");
                break;
        case EM_IP2K:
                puts("Ubicom IP2xxx");
                break;
        case EM_MAX:
                puts("MAX processor");
                break;
        case EM_CR:
                puts("National Semi. CompactRISC");
                break;
        case EM_F2MC16:
                puts("Fujitsu F2MC16");
                break;
        case EM_MSP430:
                puts("Texas Instruments msp430");
                break;
        case EM_BLACKFIN:
                puts("Analog Devices Blackfin DSP");
                break;
        case EM_SE_C33:
                puts("Seiko Epson S1C33 family");
                break;
        case EM_SEP:
                puts("Sharp embedded microprocessor");
                break;
        case EM_ARCA:
                puts("Arca RISC");
                break;
        case EM_UNICORE:
                puts("PKU-Unity & MPRC Peking Uni. mc series");
                break;
        case EM_EXCESS:
                puts("eXcess configurable cpu");
                break;
        case EM_DXP:
                puts("Icera Semi. Deep Execution Processor");
                break;
        case EM_ALTERA_NIOS2:
                puts("Altera Nios II");
                break;
        case EM_CRX:
                puts("National Semi. CompactRISC CRX");
                break;
        case EM_XGATE:
                puts("Motorola XGATE");
                break;
        case EM_C166:
                puts("Infineon C16x/XC16x");
                break;
        case EM_M16C:
                puts("Renesas M16C");
                break;
        case EM_DSPIC30F:
                puts("Microchip Technology dsPIC30F");
                break;
        case EM_CE:
                puts("Freescale Communication Engine RISC");
                break;
        case EM_M32C:
                puts("Renesas M32C");
                break;
        case EM_TSK3000:
                puts("Altium TSK3000");
                break;
        case EM_RS08:
                puts("Freescale RS08");
                break;
        case EM_SHARC:
                puts("Analog Devices SHARC family");
                break;
        case EM_ECOG2:
                puts("Cyan Technology eCOG2");
                break;
        case EM_SCORE7:
                puts("Sunplus S+core7 RISC");
                break;
        case EM_DSP24:
                puts("New Japan Radio (NJR) 24-bit DSP");
                break;
        case EM_VIDEOCORE3:
                puts("Broadcom VideoCore III");
                break;
        case EM_LATTICEMICO32:
                puts("RISC for Lattice FPGA");
                break;
        case EM_SE_C17:
                puts("Seiko Epson C17");
                break;
        case EM_TI_C6000:
                puts("Texas Instruments TMS320C6000 DSP");
                break;
        case EM_TI_C2000:
                puts("Texas Instruments TMS320C2000 DSP");
                break;
        case EM_TI_C5500:
                puts("Texas Instruments TMS320C55x DSP");
                break;
        case EM_TI_ARP32:
                puts("Texas Instruments App. Specific RISC");
                break;
        case EM_TI_PRU:
                puts("Texas Instruments Prog. Realtime Unit");
                break;
        case EM_MMDSP_PLUS:
                puts("STMicroelectronics 64bit VLIW DSP");
                break;
        case EM_CYPRESS_M8C:
                puts("Cypress M8C");
                break;
        case EM_R32C:
                puts("Renesas R32C");
                break;
        case EM_TRIMEDIA:
                puts("NXP Semi. TriMedia");
                break;
        case EM_QDSP6:
                puts("QUALCOMM DSP6");
                break;
        case EM_8051:
                puts("Intel 8051 and variants");
                break;
        case EM_STXP7X:
                puts("STMicroelectronics STxP7x");
                break;
        case EM_NDS32:
                puts("Andes Tech. compact code emb. RISC");
                break;
        case EM_ECOG1X:
                puts("Cyan Technology eCOG1X");
                break;
        case EM_MAXQ30:
                puts("Dallas Semi. MAXQ30 mc");
                break;
        case EM_XIMO16:
                puts("New Japan Radio (NJR) 16-bit DSP");
                break;
        case EM_MANIK:
                puts("M2000 Reconfigurable RISC");
                break;
        case EM_CRAYNV2:
                puts("Cray NV2 vector architecture");
                break;
        case EM_RX:
                puts("Renesas RX");
                break;
        case EM_METAG:
                puts("Imagination Tech. META");
                break;
        case EM_MCST_ELBRUS:
                puts("MCST Elbrus");
                break;
        case EM_ECOG16:
                puts("Cyan Technology eCOG16");
                break;
        case EM_CR16:
                puts("National Semi. CompactRISC CR16");
                break;
        case EM_ETPU:
                puts("Freescale Extended Time Processing Unit");
                break;
        case EM_SLE9X:
                puts("Infineon Tech. SLE9X");
                break;
        case EM_L10M:
                puts("Intel L10M");
                break;
        case EM_K10M:
                puts("Intel K10M");
                break;
        case EM_AARCH64:
                puts("ARM AARCH64");
                break;
        case EM_AVR32:
                puts("Amtel 32-bit microprocessor");
                break;
        case EM_STM8:
                puts("STMicroelectronics STM8");
                break;
        case EM_TILE64:
                puts("Tilera TILE64");
                break;
        case EM_TILEPRO:
                puts("Tilera TILEPro");
                break;
        case EM_MICROBLAZE:
                puts("Xilinx MicroBlaze");
                break;
        case EM_CUDA:
                puts("NVIDIA CUDA");
                break;
        case EM_TILEGX:
                puts("Tilera TILE-Gx");
                break;
        case EM_CLOUDSHIELD:
                puts("CloudShield");
                break;
        case EM_COREA_1ST:
                puts("KIPO-KAIST Core-A 1st gen.");
                break;
        case EM_COREA_2ND:
                puts("KIPO-KAIST Core-A 2nd gen.");
                break;
        case EM_ARCV2:
                puts("Synopsys ARCv2 ISA. ");
                break;
        case EM_OPEN8:
                puts("Open8 RISC");
                break;
        case EM_RL78:
                puts("Renesas RL78");
                break;
        case EM_VIDEOCORE5:
                puts("Broadcom VideoCore V");
                break;
        case EM_78KOR:
                puts("Renesas 78KOR");
                break;
        case EM_56800EX:
                puts("Freescale 56800EX DSC");
                break;
        case EM_BA1:
                puts("Beyond BA1");
                break;
        case EM_BA2:
                puts("Beyond BA2");
                break;
        case EM_XCORE:
                puts("XMOS xCORE");
                break;
        case EM_MCHP_PIC:
                puts("Microchip 8-bit PIC(r)");
                break;
        case EM_INTELGT:
                puts("Intel Graphics Technology");
                break;
        case EM_KM32:
                puts("KM211 KM32");
                break;
        case EM_KMX32:
                puts("KM211 KMX32");
                break;
        case EM_EMX16:
                puts("KM211 KMX16");
                break;
        case EM_EMX8:
                puts("KM211 KMX8");
                break;
        case EM_KVARC:
                puts("KM211 KVARC");
                break;
        case EM_CDP:
                puts("Paneve CDP");
                break;
        case EM_COGE:
                puts("Cognitive Smart Memory Processor");
                break;
        case EM_COOL:
                puts("Bluechip CoolEngine");
                break;
        case EM_NORC:
                puts("Nanoradio Optimized RISC");
                break;
        case EM_CSR_KALIMBA:
                puts("CSR Kalimba");
                break;
        case EM_Z80:
                puts("Zilog Z80");
                break;
        case EM_VISIUM:
                puts("Controls and Data Services VISIUMcore");
                break;
        case EM_FT32:
                puts("FTDI Chip FT32");
                break;
        case EM_MOXIE:
                puts("Moxie processor");
                break;
        case EM_AMDGPU:
                puts("AMD GPU");
                break;
        case EM_RISCV:
                puts("RISC-V");
                break;
        case EM_BPF:
                puts("Linux BPF -- in-kernel virtual machine");
                break;
        case EM_CSKY:
                puts("C-SKY");
                break;
        default:
                puts("Unknown machine");
        }

        printf("Entry: %#lx\n", hd->e_entry);

        printf("Start of program headers: %lu\n", hd->e_phoff);

        printf("Start of section headers: %lu\n", hd->e_shoff);

        printf("Flags: %x\n", hd->e_flags);

        printf("Size of this header: %u\n", hd->e_ehsize);

        printf("Size of program headers: %u\n", hd->e_phentsize);

        printf("Number of program headers: %u\n", hd->e_phnum);

        printf("Size of section headers: %u\n", hd->e_shentsize);

        printf("Number of section headers: %u\n", hd->e_shnum);

        printf("Section header string table index: %u\n", hd->e_shstrndx);
}

// TODO: Make pretty
void elf_program_header_dump(const Elf64_Phdr *const ph, const size_t n)
{
        puts("Program headers:");
        puts("Type\tOffset\tVirtAddr\tPhysAddr\tFileSize\tMemSize\tFlags\t"
             "Align");

        for (size_t i = 0; i < n; ++i) {
                switch ((ph + i)->p_type) {
                case PT_NULL:
                        printf("NULL");
                        break;
                case PT_LOAD:
                        printf("LOAD");
                        break;
                case PT_DYNAMIC:
                        printf("DYNAMIC");
                        break;
                case PT_INTERP:
                        printf("INTERP");
                        break;
                case PT_NOTE:
                        printf("NOTE");
                        break;
                case PT_SHLIB:
                        printf("SHLIB");
                        break;
                case PT_PHDR:
                        printf("PHDR");
                        break;
                case PT_TLS:
                        printf("TLS");
                        break;
                case PT_GNU_EH_FRAME:
                        printf("GNU_EH_FRAME");
                        break;
                case PT_GNU_STACK:
                        printf("GNU_STACK");
                        break;
                case PT_GNU_RELRO:
                        printf("GNU_RELRO");
                        break;
                case PT_GNU_PROPERTY:
                        printf("GNU_PROPERTY");
                        break;
                default:
                        printf("UNKNOWN");
                }

                printf("\t%#.16lx", (ph + i)->p_offset);

                printf("\t%#.16lx", (ph + i)->p_vaddr);

                printf("\t%#.16lx", (ph + i)->p_paddr);

                printf("\t%#.16lx", (ph + i)->p_filesz);

                printf("\t%#.16lx\t", (ph + i)->p_memsz);

                printf("%c", (ph + i)->p_flags & PF_R ? 'r' : ' ');
                printf("%c", (ph + i)->p_flags & PF_W ? 'w' : ' ');
                printf("%c", (ph + i)->p_flags & PF_X ? 'x' : ' ');

                printf("\t%#.16lx", (ph + i)->p_align);

                puts("");
        }
}
