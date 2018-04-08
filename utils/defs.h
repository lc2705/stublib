/*
 * Copyright (c) 2018 Chen Jingpiao <chenjingpiao@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef READELF_DEFS_H
#define READELF_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

extern int addr_bits;
extern unsigned char elf_class;

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
	uint16_t	e_type;			/* Object file type */
	uint16_t	e_machine;		/* Architecture */
	uint32_t	e_version;		/* Object file version */
	uint64_t	e_entry;		/* Entry point virtual address */
	uint64_t	e_phoff;		/* Program header table file offset */
	uint64_t	e_shoff;		/* Section header table file offset */
	uint32_t	e_flags;		/* Processor-specific flags */
	uint16_t	e_ehsize;		/* ELF header size in bytes */
	uint16_t	e_phentsize;		/* Program header table entry size */
	uint16_t	e_phnum;		/* Program header table entry count */
	uint16_t	e_shentsize;		/* Section header table entry size */
	uint16_t	e_shnum;		/* Section header table entry count */
	uint16_t	e_shstrndx;		/* Section header string table index */
} Elf_Ehdr;

extern Elf_Ehdr elf_header;
extern bool do_header;
extern bool do_segments;
extern bool do_sections;
extern bool do_symbol;

extern void read_elf_header(const int fd);
extern void display_elf_header(const int fd);
extern const char *get_file_type(unsigned int type);

typedef struct {
	uint32_t	sh_name;		/* Section name (string tbl index) */
	uint32_t	sh_type;		/* Section type */
	uint64_t	sh_flags;		/* Section flags */
	uint64_t	sh_addr;		/* Section virtual addr at execution */
	uint64_t	sh_offset;		/* Section file offset */
	uint64_t	sh_size;		/* Section size in bytes */
	uint32_t	sh_link;		/* Link to another section */
	uint32_t	sh_info;		/* Additional section information */
	uint64_t	sh_addralign;		/* Section alignment */
	uint64_t	sh_entsize;		/* Entry size if section holds table */
} Elf_Shdr;

typedef struct {
	uint32_t	st_name;		/* Symbol name (string tbl index) */
	unsigned char	st_info;		/* Symbol type and binding */
	unsigned char	st_other;		/* Symbol visibility */
	uint16_t	st_shndx;		/* Section index */
	uint64_t	st_value;		/* Symbol value */
	uint64_t	st_size;		/* Symbol size */
} Elf_Sym;

extern void display_section_headers(const int fd);

typedef struct {
	uint32_t	p_type;			/* Segment type */
	uint32_t	p_flags;		/* Segment flags */
	uint64_t	p_offset;		/* Segment file offset */
	uint64_t	p_vaddr;		/* Segment virtual address */
	uint64_t	p_paddr;		/* Segment physical address */
	uint64_t	p_filesz;		/* Segment size in file */
	uint64_t	p_memsz;		/* Segment size in memory */
	uint64_t	p_align;		/* Segment alignment */
} Elf_Phdr;

extern void display_segment_headers(const int fd);
extern void display_symbol_table(const int fd);

extern void error_msg_and_die(const char *fmt, ...);
extern void perror_msg_and_die(const char *str);

#endif /* READELF_DEFS_H */
