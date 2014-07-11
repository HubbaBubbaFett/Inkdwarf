#ifndef __INKDWARF_H
#define __INKDWARF_H

#include <stdint.h> // uintX_t
#include <stddef.h> // size_t

// ELF
// TODO: Assume 64 bit

#define SHN_UNDEF   0       /* undef section */

struct elf_ident {
    union {
        struct {
            char e_magic0;
            char e_magic1;
            char e_magic2;
            char e_magic3;
        } magics;
        uint32_t e_magic;
    } magic;                            /* magic = \177ELF */
    uint8_t e_class;                    /* format: 1 = 32 bit, 2 = 64 */
    uint8_t e_data;                     /* endianness: 1 = little, 2 = big */
    uint8_t e_version;                  /* elf version: 1 = original */
    uint8_t e_osabi;                    /* os abi */
    uint8_t e_abiversion;               /* abi version */
    char e_pad[];                       /* padding */
};

#define EI_NIDENT (16)

struct elf_file_header {
    unsigned char e_ident[EI_NIDENT];   /* magic and stuff (struct elf_ident) */
    uint16_t e_type;                    /* 1 = relocate, 2 = exe, 3 = shared, 4 = core */
    uint16_t e_machine;                 /* architechture */
    uint32_t e_version;                 /* elf version */
    uint64_t e_entry;                   /* start address */
    uint64_t e_phoff;                   /* program header offset */
    uint64_t e_shoff;                   /* section header offset */
    uint32_t e_flags;                   /* interpretation of flags dep of arch */
    uint16_t e_ehsize;                  /* header size */
    uint16_t e_phentsize;               /* program header size */
    uint16_t e_phnum;                   /* program header entries */
    uint16_t e_shentsize;               /* section header size */
    uint16_t e_shnum;                   /* section header entries */
    uint16_t e_shstrndx;                /* section header index that contain section names */
};

struct elf_section_header {
    uint32_t sh_name;                   /* section name */
    uint32_t sh_type;                   /* section type */
    uint64_t sh_flags;                  /* section type */
    uint64_t sh_addr;                   /* section virtual addr at execution */
    uint64_t sh_offset;                 /* section file offset */
    uint64_t sh_size;                   /* section size in bytes */
    uint32_t sh_link;                   /* link to another section */
    uint32_t sh_info;                   /* additional section information */
    uint64_t sh_addralign;              /* section alignment */
    uint64_t sh_entsize;                /* entry size if section holds table */
};

struct elf_ctx {
    int elf_fd;
    size_t elf_size;
    void *elf_start_address;        /* TODO: not assuming 0x400000 */
    struct elf_file_header *elf_fh; /* = start of file */
    void *dwarf_debug_str;                                  /* = .debug_str */
    struct elf_section_header *dwarf_debug_info_sh;         /* = .debug_info */
    struct elf_section_header *dwarf_debug_abbrev_sh;       /* = .debug_abbrev */
    struct elf_section_header *dwarf_debug_types_sh;        /* = .debug_types */

    struct abbrev **abbrev_array;   // parsed abbrev
};

// !ELF

// DWARF

#include <dwarf.h>

// p. 143 dwarf4.0 pdf
struct dwarf_compilation_unit_header {
    uint32_t length;
    uint16_t version;
    uint32_t abbrev_offset;
    uint8_t addr_size;
} __attribute__((packed));

// p. 144 dwarf4.0 pdf
struct dwarf_types_unit_header {
    uint32_t length;
    uint16_t version;
    uint32_t abbrev_offset; // or 64 bit
    uint8_t addr_size;
    uint64_t signature;
    uint32_t offset;
} __attribute__((packed));

struct dwarf_compilation_unit {
    uint8_t index;
    uint32_t producer;
    uint8_t language;
    uint32_t name;
    uint32_t comp_dir;
    uint64_t low_pc;
    uint64_t high_pc;
    uint32_t stmt_list;
} __attribute__((packed));

// !DWARF

#endif
