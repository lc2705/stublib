/*
 * Copyright (c) 2018 Chen Jingpiao <chenjingpiao@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "defs.h"

#define EXTEND_SECTION_HEADER(type, src, dest)				\
	do {								\
		(dest)->sh_name		= ((type *)(src))->sh_name;	\
		(dest)->sh_type		= ((type *)(src))->sh_type;	\
		(dest)->sh_flags	= ((type *)(src))->sh_flags;	\
		(dest)->sh_addr		= ((type *)(src))->sh_addr;	\
		(dest)->sh_offset	= ((type *)(src))->sh_offset;	\
		(dest)->sh_size		= ((type *)(src))->sh_size;	\
		(dest)->sh_link		= ((type *)(src))->sh_link;	\
		(dest)->sh_info		= ((type *)(src))->sh_info;	\
		(dest)->sh_addralign	= ((type *)(src))->sh_addralign;\
		(dest)->sh_entsize	= ((type *)(src))->sh_entsize;	\
	} while (0)

#define EXTEND_SYMBOL_TABLE(type, src, dest)				\
	do {								\
		(dest)->st_name		= ((type *)(src))->st_name;	\
		(dest)->st_info		= ((type *)(src))->st_info;	\
		(dest)->st_other	= ((type *)(src))->st_other;	\
		(dest)->st_shndx	= ((type *)(src))->st_shndx;	\
		(dest)->st_value	= ((type *)(src))->st_value;	\
		(dest)->st_size		= ((type *)(src))->st_size;	\
	} while (0)

static Elf_Shdr *section_header;
static Elf_Sym *symbol_table;
static void *shstr_table;

static void read_section_headers(const int fd)
{
	if (lseek(fd, elf_header.e_shoff, SEEK_SET) == -1)
		perror_msg_and_die("lseek");

	int len;
	if (elf_class == ELFCLASS32)
		len = elf_header.e_shnum * sizeof(Elf32_Shdr);
	else
		len = elf_header.e_shnum * sizeof(Elf64_Shdr);

	void *buf = malloc(len);
	if (!buf)
		perror("malloc");
	if (read(fd, buf, len) != len)
		error_msg_and_die("Short read of section headers.\n");

	section_header = malloc(elf_header.e_shnum * sizeof(*section_header));
	if (!section_header)
		perror("malloc");

	int i;
	void *ptr = buf;
	for (i = 0; i < elf_header.e_shnum; i++) {
		if (elf_class == ELFCLASS32) {
			EXTEND_SECTION_HEADER(Elf32_Shdr, ptr, &section_header[i]);
			ptr += sizeof(Elf32_Shdr);
		} else {
			EXTEND_SECTION_HEADER(Elf64_Shdr, ptr, &section_header[i]);
			ptr += sizeof(Elf64_Shdr);
		}
	}
	free(buf);
}

static void read_shstr_table(const int fd)
{
	if (elf_header.e_shstrndx > elf_header.e_shnum - 1)
		error_msg_and_die("Do not have string table.\n");

	if (lseek(fd, section_header[elf_header.e_shstrndx].sh_offset, SEEK_SET) == -1)
		perror_msg_and_die("lseek");

	int len = section_header[elf_header.e_shstrndx].sh_size;
	shstr_table = malloc(len);
	if (!shstr_table)
		perror_msg_and_die("malloc");
	if (read(fd, shstr_table, len) != len)
		error_msg_and_die("Short read of section string table.\n");
}

static const char *get_section_name(unsigned int offset)
{
	return shstr_table + offset;
}

static const char *get_section_type(unsigned int type)
{
	static char buf[32];

	switch (type) {
	case SHT_NULL:
		return "NULL";
	case SHT_PROGBITS:
		return "PROGBITS";
	case SHT_SYMTAB:
		return "SYMTAB";
	case SHT_STRTAB:
		return "STRTAB";
	case SHT_RELA:
		return "RELA";
	case SHT_HASH:
		return "HASH";
	case SHT_DYNAMIC:
		return "DYNAMIC";
	case SHT_NOTE:
		return "NOTE";
	case SHT_NOBITS:
		return "NOBITS";
	case SHT_REL:
		return "REL";
	case SHT_SHLIB:
		return "SHLIB";
	case SHT_DYNSYM:
		return "DYNSYM";
	case SHT_INIT_ARRAY:
		return "INIT_ARRAY";
	case SHT_FINI_ARRAY:
		return "FINI_ARRAY";
	case SHT_PREINIT_ARRAY:
		return "PREINIT_ARRAY";
	case SHT_GROUP:
		return "GROUP";
	case SHT_SYMTAB_SHNDX:
		return "SYMTAB_SHNDX";
	case SHT_NUM:
		return "NUM";
	case SHT_GNU_ATTRIBUTES:
		return "GNU_ATTRIBUTES";
	case SHT_GNU_HASH:
		return "GNU_HASH";
	case SHT_GNU_LIBLIST:
		return "GNU_LIBLIST";
	case SHT_CHECKSUM:
		return "CHECKSUM";
	case SHT_LOSUNW:
		return "LOSUNW";
	case SHT_SUNW_COMDAT:
		return "SUNW_COMDAT";
	case SHT_SUNW_syminfo:
		return "SUNW_SYMINFO";
	case SHT_GNU_verdef:
		return "VERDEF";
	case SHT_GNU_verneed:
		return "VERNEED";
	case SHT_GNU_versym:
		return "VERSYM";
	case SHT_LOPROC...SHT_HIPROC:
		return "processor-specific";
	case SHT_LOUSER...SHT_HIUSER:
		return "application-specific";
	default:
		if (type >= SHT_LOOS && type <= SHT_HIOS)
			return "OS-specific";
		snprintf(buf, sizeof(buf), "%08x: <unknown>", type);
		return buf;
	}
}

static void print_section_flags(uint64_t sh_flags)
{
	struct {
		unsigned int val;
		const char *str;
	} flags[] = {
		{ SHF_WRITE,		"W" },
		{ SHF_ALLOC,		"A" },
		{ SHF_EXECINSTR,	"X" },
		{ SHF_MERGE,		"M" },
		{ SHF_STRINGS,		"S" },
		{ SHF_INFO_LINK,	"I" },
		{ SHF_LINK_ORDER,	"L" },
		{ SHF_OS_NONCONFORMING,	"O" },
		{ SHF_GROUP,		"G" },
		{ SHF_TLS,		"T" },
		{ SHF_COMPRESSED,	"C" },
		{ SHF_ORDERED,		"o" },
		{ SHF_EXCLUDE,		"E" }
	};
	int i;
	int count = 7;

	printf("  ");
	for (i = 0; i < ARRAY_SIZE(flags); i++)
		if (sh_flags & flags[i].val) {
			printf("%s", flags[i].str);
			sh_flags &= ~flags[i].val;
			count--;
		}

	if (sh_flags) {
		printf("/* %#llx */", (unsigned long long) sh_flags);
		count = 0;
	}
	while (count--)
		putchar(' ');
}

static void print_section_flags_key(void)
{
	printf ("Key to Flags:\n\
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n\
  L (link order), O (extra OS processing required), G (group), T (TLS),\n\
  C (compressed), o (OS specific), E (exclude),\n  ");
}

static void print_section_header(const Elf_Shdr *hdr)
{
	printf("%-17s", get_section_name(hdr->sh_name));
	printf(" %-15.15s  ", get_section_type(hdr->sh_type));
	printf("%-16.*llx", addr_bits / 4, (unsigned long long) hdr->sh_addr);
	printf("  %8.8llx", (unsigned long long) hdr->sh_offset);
	printf("\n       ");
	printf("%-16.*llx  %-16.*llx",
	       addr_bits / 4, (unsigned long long) hdr->sh_size,
	       addr_bits / 4, (unsigned long long) hdr->sh_entsize);
	print_section_flags(hdr->sh_flags);
	printf(" %2u   %3u     %lu\n",
	       hdr->sh_link, hdr->sh_info,
	       (unsigned long) hdr->sh_addralign);
}

void display_section_headers(const int fd)
{
//	if (do_sections) {
		if (elf_header.e_shnum == 0) {
			if (elf_header.e_shoff != 0)
				error_msg_and_die("Has non-zero offset"
						  ", buf no section headers.\n");
			else {
				printf("There are no sections in this file.\n");
				return;
			}
		}
//		if (!do_header)
			printf("There are %d section headers"
			       ", starting at offset %lld:\n\n",
			       elf_header.e_shnum,
			       (unsigned long long) elf_header.e_shoff);
		read_section_headers(fd);
		if (!shstr_table)
			read_shstr_table(fd);

		if (elf_header.e_shnum == 1)
			printf("Section Header:\n");
		else
			printf("Section Headers:\n");

		printf("  [Nr] Name              Type             Address           Offset\n"
		       "       Size              EntSize          Flags  Link  Info  Align\n");

		int i;
		for (i = 0; i < elf_header.e_shnum; i++) {
			printf("  [%2u] ", i);
			print_section_header(section_header + i);
		}
//	}
}

static Elf_Sym *read_symbol_table(const int fd, const Elf_Shdr *sym_section)
{
	if (lseek(fd, sym_section->sh_offset, SEEK_SET) == -1)
		perror_msg_and_die("lseek");

	void *buf = malloc(sym_section->sh_size);

	if (!buf)
		perror_msg_and_die("malloc");

	if (read(fd, buf, sym_section->sh_size) != sym_section->sh_size)
		perror_msg_and_die("read");

	int nums = sym_section->sh_size / sym_section->sh_entsize;
	int i;

	Elf_Sym *symtbl = malloc(nums * sizeof(Elf_Sym));
	if (!symtbl)
		perror_msg_and_die("malloc");
	for (i = 0; i < nums; i++) {
		if (elf_class == ELFCLASS32)
			EXTEND_SYMBOL_TABLE(Elf32_Sym, (Elf32_Sym *) buf + i, symtbl + i);
		else
			EXTEND_SYMBOL_TABLE(Elf64_Sym, (Elf64_Sym *) buf + i, symtbl + i);
	}
	free(buf);
	return symtbl;
}

const char *get_symbol_name(const int fd, const unsigned int offset,
				   const unsigned int link)
{
	static char buf[64];

	if (link < elf_header.e_shnum) {
		if (lseek(fd, section_header[link].sh_offset + offset, SEEK_SET) == -1)
			perror_msg_and_die("lseek");
		read(fd, buf, sizeof(buf));
		return buf;
	}
    
	snprintf(buf, sizeof(buf), "<unknown>: %d", offset);
}

static const char *get_symbol_type(unsigned char info)
{
	unsigned char type = info & 0xF;
	static char buf[32];

	switch (type) {
	case STT_NOTYPE:
		return "NOTYPE";
	case STT_OBJECT:
		return "OBJECT";
	case STT_FUNC:
		return "FUNC";
	case STT_SECTION:
		return "SECTION";
	case STT_FILE:
		return "FILE";
	case STT_COMMON:
		return "COMMON";
	case STT_TLS:
		return "TLS";
	default:
		snprintf(buf, sizeof(buf), "<unknown>: %d", type);
		return buf;
	}
}

static const char *get_symbol_binding(unsigned char info)
{
	unsigned char bindind = info >> 4;
	static char buf[32];

	switch (bindind) {
	case STB_LOCAL:
		return "LOCAL";
	case STB_GLOBAL:
		return "GLOBAL";
	case STB_WEAK:
		return "WEAK";
	default:
		snprintf(buf, sizeof(buf), "<unknown>: %d", bindind);
		return buf;
	}
}

static const char *get_symbol_visibility(unsigned char vis)
{
	static char buf[32];

	switch (vis) {
	case STV_DEFAULT:
		return "DEFAULT";
	case STV_INTERNAL:
		return "INTERNAL";
	case STV_HIDDEN:
		return "HIDDEN";
	case STV_PROTECTED:
		return "PROTECTED";
	default:
		snprintf(buf, sizeof(buf), "<unknown>: %d", vis);
		return buf;
	}
}

static const char *get_symbol_index_type(unsigned int shndx)
{
	static char buf[32];

	switch (shndx) {
	case SHN_UNDEF:
		return "UND";
	case SHN_ABS:
		return "ABS";
	case SHN_COMMON:
		return "COM";
	default:
		snprintf(buf, sizeof(buf), "%d", shndx);
		return buf;
	}
}

static void print_symbol_table(const int fd, const Elf_Sym *symtbl, const int n,
			       const unsigned int link)
{
	int i;

	printf("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
	for (i = 0; i < n; i++) {
		printf("%6d: %16.*llx %5lld %-7s %-6s %-7s %4s %s\n",
		       i, addr_bits / 4, (unsigned long long) symtbl[i].st_value,
		       (unsigned long long) symtbl[i].st_size,
		       get_symbol_type(symtbl[i].st_info),
		       get_symbol_binding(symtbl[i].st_info),
		       get_symbol_visibility(symtbl[i].st_other),
		       get_symbol_index_type(symtbl[i].st_shndx),
		       get_symbol_name(fd, symtbl[i].st_name, link));
	}
}

void display_symbol_table(const int fd)
{
//	if (do_symbol) {
		if (!section_header)
			read_section_headers(fd);

		int i;

		for (i = 0; i < elf_header.e_shnum; i++) {
			if (section_header[i].sh_type != SHT_SYMTAB
			    && section_header[i].sh_type != SHT_DYNSYM)
				continue;
			Elf_Sym *symtbl = read_symbol_table(fd, section_header + i);
			if (!shstr_table)
				read_shstr_table(fd);
			unsigned long long entries =
					   section_header[i].sh_size / section_header[i].sh_entsize;
			printf("Symbol table '%s' contains %llu entries:\n",
			       get_section_name(section_header[i].sh_name), entries);
			print_symbol_table(fd, symtbl, entries,
					   section_header[i].sh_link);
			free(symtbl);
		}
//	}
}

void* get_symbol_by_name(const int fd, char* sym_name) {
    int i = 0, j = 0;
	if (!section_header) {
	    read_section_headers(fd);
	}

    for (i = 0; i < elf_header.e_shnum; i++) {
	    if (section_header[i].sh_type != SHT_SYMTAB 
			    && section_header[i].sh_type != SHT_DYNSYM)
			continue;
		Elf_Sym *symtbl = read_symbol_table(fd, section_header + i);
		if (!shstr_table) {
		    read_shstr_table(fd);
		}
		unsigned long long entries = section_header[i].sh_size / section_header[i].sh_entsize;
		char buf[64];
		for (j = 0; j < entries; j++) {
               int link = section_header[i].sh_link;
			   if (link < elf_header.e_shnum) {
			       if (lseek(fd, section_header[link].sh_offset + symtbl[j].st_name, SEEK_SET) == -1)
					   return NULL;
				   read(fd, buf, sizeof(buf));
//				   printf("%s\n", buf);
				   if (strlen(buf) && strcmp(buf, sym_name) == 0) {
				       return (void*)symtbl[j].st_value;
				   }
			   }
		}
	}
	return NULL;
}

void clean_section_env() {
    if (section_header) {
	    free(section_header);
		section_header = NULL;
	}
	if (shstr_table) {
	    free(shstr_table);
		shstr_table = NULL;
	}
}
