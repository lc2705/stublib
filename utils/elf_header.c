/*
 * Copyright (c) 2018 Chen Jingpiao <chenjingpiao@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "defs.h"

#include <unistd.h>

#define EXTEND_ELF_HEADER(type, addr)					\
	do {								\
		elf_header.e_type	= ((type *)(addr))->e_type;	\
		elf_header.e_machine	= ((type *)(addr))->e_machine;	\
		elf_header.e_version	= ((type *)(addr))->e_version;	\
		elf_header.e_entry	= ((type *)(addr))->e_entry;	\
		elf_header.e_phoff	= ((type *)(addr))->e_phoff;	\
		elf_header.e_shoff	= ((type *)(addr))->e_shoff;	\
		elf_header.e_flags	= ((type *)(addr))->e_flags;	\
		elf_header.e_ehsize	= ((type *)(addr))->e_ehsize;	\
		elf_header.e_phentsize	= ((type *)(addr))->e_phentsize;\
		elf_header.e_phnum	= ((type *)(addr))->e_phnum;	\
		elf_header.e_shentsize	= ((type *)(addr))->e_shentsize;\
		elf_header.e_shnum	= ((type *)(addr))->e_shnum;	\
		elf_header.e_shstrndx	= ((type *)(addr))->e_shstrndx;	\
	} while (0)

void read_elf_header(const int fd)
{
	int n;

	n = read(fd, elf_header.e_ident, sizeof(elf_header.e_ident));
	if (n != sizeof(elf_header.e_ident)) {
		if (n == -1)
			perror_msg_and_die("read");
		else
			error_msg_and_die("Short read of ELF header.\n");
	}

	Elf32_Ehdr elf32_hdr;
	Elf64_Ehdr elf64_hdr;
	int len;
	void *addr;

	if (elf_header.e_ident[EI_CLASS] == ELFCLASS32) {
		const size_t offset = sizeof(elf32_hdr.e_ident);
		len = sizeof(elf32_hdr) - offset;
		addr = (void *) &elf32_hdr + offset;
	} else if (elf_header.e_ident[EI_CLASS] == ELFCLASS64) {
		const size_t offset = sizeof(elf64_hdr.e_ident);
		len = sizeof(elf64_hdr) - offset;
		addr = (void *) &elf64_hdr + offset;
	} else
		error_msg_and_die("Invail ELF class.\n");

	n = read(fd, addr, len);
	if (n != len) {
		if (n == -1)
			perror_msg_and_die("read");
		else
			error_msg_and_die("Short read of ELF header.\n");
	}
	if (elf_header.e_ident[EI_CLASS] == ELFCLASS32)
		EXTEND_ELF_HEADER(Elf32_Ehdr, &elf32_hdr);
	else
		EXTEND_ELF_HEADER(Elf64_Ehdr, &elf64_hdr);
}

static const char *get_elf_class(unsigned char class)
{
	static char buf[32];

	switch (class) {
	case ELFCLASSNONE:
		return "none";
	case ELFCLASS32:
		return "ELF32";
	case ELFCLASS64:
		return "ELF64";
	default:
		snprintf(buf, sizeof(buf), "<unknown: %x>", class);
		return buf;
	}
};

static const char *get_data_encoding(unsigned char encoding)
{
	static char buf[32];

	switch (encoding) {
	case ELFDATANONE:
		return "none";
	case ELFDATA2LSB:
		return "2's complement, little endian";
	case ELFDATA2MSB:
		return "2's complement, big endian";
	default:
		snprintf(buf, sizeof(buf), "<unknown: %x>", encoding);
		return buf;
	}
}

static const char *get_osabi(unsigned char osabi)
{
	static char buf[32];

	switch (osabi) {
	case ELFOSABI_NONE:
		return "UNIX - System V";
	case ELFOSABI_HPUX:
		return "UNIX - HP-UX";
	case ELFOSABI_NETBSD:
		return "UNIX - NetBSD";
	case ELFOSABI_GNU:
		return "UNIX - GNU";
	case ELFOSABI_SOLARIS:
		return "UNIX - Solaris";
	case ELFOSABI_AIX:
		return "UNIX - AIX";
	case ELFOSABI_IRIX:
		return "UNIX - IRIX";
	case ELFOSABI_FREEBSD:
		return "UNIX - FreeBSD";
	case ELFOSABI_TRU64:
		return "UNIX - TRU64";
	case ELFOSABI_MODESTO:
		return "Novell Modesto";
	case ELFOSABI_OPENBSD:
		return "UNIX - OpenBSD";
	case ELFOSABI_ARM_AEABI:
		return "ARM EABI";
	case ELFOSABI_ARM:
		return "ARM";
	case ELFOSABI_STANDALONE:
		return "Standalone (embedded) application";
	default:
		snprintf(buf, sizeof(buf), "<unknown: %x>", osabi);
		return buf;
	}
}

const char *get_file_type(unsigned int type)
{
	static char buf[32];

	switch (type) {
	case ET_NONE:
		return "NONE (None)";
	case ET_REL:
		return "REL (Relocatable file)";
	case ET_EXEC:
		return "EXEC (Executable file)";
	case ET_DYN:
		return "DYN (Shared object file)";
	case ET_CORE:
		return "CORE (Core file)";
	case ET_LOOS...ET_HIOS:
		snprintf(buf, sizeof(buf), "Processor Specific: (%x)", type);
		return buf;
	case ET_LOPROC...ET_HIPROC:
		snprintf(buf, sizeof(buf), "OS Specific: (%x)", type);
		return buf;
	default:
		snprintf(buf, sizeof(buf), "<unknown>: %x", type);
		return buf;
	}
}

static const char *get_machine_name(unsigned int machine)
{
	static char buf[32];

	switch (machine) {
	case EM_NONE:
		return "None";
	case EM_M32:
		return "AT&T WE 32100";
	case EM_SPARC:
		return "SUN SPARC";
	case EM_386:
		return "Intel 80386";
	case EM_68K:
		return "Motorola m68k family";
	case EM_88K:
		return "Motorola m88k family";
	case EM_860:
		return "Intel 80860";
	case EM_MIPS:
		return "MIPS R3000 big-endian";
	case EM_S370:
		return "IBM System/370";
	case EM_MIPS_RS3_LE:
		return "MIPS R3000 little-endian";

	case EM_PARISC:
		return "HPPA";
	case EM_VPP500:
		return "Fujitsu VPP500";
	case EM_SPARC32PLUS:
		return "Sun's \"v8plus\"";
	case EM_960:
		return "Intel 80960";
	case EM_PPC:
		return "PowerPC";
	case EM_PPC64:
		return "PowerPC 64-bit";
	case EM_S390:
		return "IBM S390";

	case EM_V800:
		return "NEC V800 series";
	case EM_FR20:
		return "Fujitsu FR20";
	case EM_RH32:
		return "TRW RH-32";
	case EM_RCE:
		return "Motorola RCE";
	case EM_ARM:
		return "ARM";
	case EM_FAKE_ALPHA:
		return "Digital Alpha";
	case EM_SH:
		return "Hitachi SH";
	case EM_SPARCV9:
		return "SPARC v9 64-bit";
	case EM_TRICORE:
		return "Siemens Tricore";
	case EM_ARC:
		return "Argonaut RISC Core";
	case EM_H8_300:
		return "Hitachi H8/300";
	case EM_H8_300H:
		return "Hitachi H8/300H";
	case EM_H8S:
		return "Hitachi H8S";
	case EM_H8_500:
		return "Hitachi H8/500";
	case EM_IA_64:
		return "Intel Merced";
	case EM_MIPS_X:
		return "Stanford MIPS-X";
	case EM_COLDFIRE:
		return "Motorola Coldfire";
	case EM_68HC12:
		return "Motorola M68HC12";
	case EM_MMA:
		return "Fujitsu MMA Multimedia Accelerator";
	case EM_PCP:
		return "Siemens PCP";
	case EM_NCPU:
		return "Sony nCPU embeeded RISC";
	case EM_NDR1:
		return "Denso NDR1 microprocessor";
	case EM_STARCORE:
		return "Motorola Start*Core processor";
	case EM_ME16:
		return "Toyota ME16 processor";
	case EM_ST100:
		return "STMicroelectronic ST100 processor";
	case EM_TINYJ:
		return "Advanced Logic Corp. Tinyj emb.fam";
	case EM_X86_64:
		return "AMD x86-64 architecture";
	case EM_PDSP:
		return "Sony DSP Processor";

	case EM_FX66:
		return "Siemens FX66 microcontroller";
	case EM_ST9PLUS:
		return "STMicroelectronics ST9+ 8/16 mc";
	case EM_ST7:
		return "STmicroelectronics ST7 8 bit mc";
	case EM_68HC16:
		return "Motorola MC68HC16 microcontroller";
	case EM_68HC11:
		return "Motorola MC68HC11 microcontroller";
	case EM_68HC08:
		return "Motorola MC68HC08 microcontroller";
	case EM_68HC05:
		return "Motorola MC68HC05 microcontroller";
	case EM_SVX:
		return "Silicon Graphics SVx";
	case EM_ST19:
		return "STMicroelectronics ST19 8 bit mc";
	case EM_VAX:
		return "Digital VAX";
	case EM_CRIS:
		return "Axis Communications 32-bit embedded processor";
	case EM_JAVELIN:
		return "Infineon Technologies 32-bit embedded processor";
	case EM_FIREPATH:
		return "Element 14 64-bit DSP Processor";
	case EM_ZSP:
		return "LSI Logic 16-bit DSP Processor";
	case EM_MMIX:
		return "Donald Knuth's educational 64-bit processor";
	case EM_HUANY:
		return "Harvard University machine-independent object files";
	case EM_PRISM:
		return "SiTera Prism";
	case EM_AVR:
		return "Atmel AVR 8-bit microcontroller";
	case EM_FR30:
		return "Fujitsu FR30";
	case EM_D10V:
		return "Mitsubishi D10V";
	case EM_D30V:
		return "Mitsubishi D30V";
	case EM_V850:
		return "NEC v850";
	case EM_M32R:
		return "Mitsubishi M32R";
	case EM_MN10300:
		return "Matsushita MN10300";
	case EM_MN10200:
		return "Matsushita MN10200";
	case EM_PJ:
		return "picoJava";
	case EM_OPENRISC:
		return "OpenRISC 32-bit embedded processor";
	case EM_ARC_A5:
		return "ARC Cores Tangent-A5";
	case EM_XTENSA:
		return "Tensilica Xtensa Architecture";
	case EM_ALTERA_NIOS2:
		return "Altera Nios II";
	case EM_AARCH64:
		return "ARM AARCH64";
	case EM_TILEPRO:
		return "Tilera TILEPro";
	case EM_MICROBLAZE:
		return "Xilinx MicroBlaze";
	case EM_TILEGX:
		return "Tilera TILE-Gx";
	default:
		snprintf(buf, sizeof(buf), "<unknown>: %#x", machine);
		return buf;
	}
}

void display_elf_header(const int fd)
{
//	if (do_header) {
		int i;
		const char *str;

		printf("ELF Header:\n");
		printf("  Magic:   ");
		for (i = 0; i < EI_NIDENT; i++)
			printf("%2.2x ", elf_header.e_ident[i]);
		printf("\n");
		printf("  Class:                             %s\n",
		       get_elf_class(elf_header.e_ident[EI_CLASS]));
		printf("  Data:                              %s\n",
		       get_data_encoding(elf_header.e_ident[EI_DATA]));
		printf("  Version:                           %d %s\n",
			elf_header.e_ident[EI_VERSION],
			elf_header.e_ident[EI_VERSION] == EV_CURRENT
			? "(current)"
			: (elf_header.e_ident[EI_VERSION] == EV_NONE ? "none" : ""));
		printf("  OS/ABI:                            %s\n",
		       get_osabi(elf_header.e_ident[EI_OSABI]));
		printf("  ABI Version:                       %d\n",
		       elf_header.e_ident[EI_ABIVERSION]);
		printf("  Type:                              %s\n",
		       get_file_type(elf_header.e_type));
		printf("  Machine:                           %s\n",
		       get_machine_name(elf_header.e_machine));
		printf("  Version:                           0x%x\n",
		       elf_header.e_version);
		printf("  Entry point address:               0x%llx\n",
		       (unsigned long long) elf_header.e_entry);
		printf("  Start of program headers:          %lld (bytes into file)\n",
		       (unsigned long long) elf_header.e_phoff);
		printf("  Start of section headers:          %lld (bytes into file)\n",
		       (unsigned long long) elf_header.e_shoff);
		printf("  Flags:                             0x%x\n",
		       elf_header.e_flags);
		printf("  Size of this header:               %d (bytes)\n",
		       (unsigned int) elf_header.e_ehsize);
		printf("  Size of program headers:           %d (bytes)\n",
		       (unsigned int) elf_header.e_phentsize);
		printf("  Number of program headers:         %d\n",
		       (unsigned int) elf_header.e_phnum);
		printf("  Size of section headers:           %d (bytes)\n",
		       (unsigned int) elf_header.e_shentsize);
		printf("  Number of section headers:         %d\n",
		       (unsigned int) elf_header.e_shnum);
		printf("  Section header string table index: %d\n",
		       (unsigned int) elf_header.e_shstrndx);
//	}
}
