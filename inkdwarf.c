#ifndef __INKDWARF__
#define __INKDWARF__

/*
 * TODO:
 *  - enums
 *  - unions
 *  - bit stuff in structs
 *
 *  - kernel static/module
 *  - c++
 */
#ifndef NDEBUG

#define _DEFAULT_SOURCE
// #define _GNU_SOURCE     // asprintf()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
//#include <string.h>
//#include <dwarf.h>
//#include <libdwarf.h>

#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>   // backtrace()

#include <bsd/sys/queue.h>

#include <stdint.h> // uintX_t
#include <stddef.h> // size_t


void
hexdump_addr(void *ptr, size_t len, void *start_addr)
{
    unsigned char *buffer = ptr, c;
    size_t idx = 0;
    char ascii[16 + 1] = { 0 };
    while (1) {
        if (0 == idx % 16) fprintf(stderr, "%08lx ", (size_t)start_addr + idx);
        if (idx < len) {
            fprintf(stderr, "%02x ", c = buffer[idx]);
            ascii[idx%16] = isgraph(c) ? c : '.';
        } else {
            fprintf(stderr, "   ");
            ascii[idx%16] = '\0';
        }
        if (0 == ++idx % 8)
            fputc(' ', stderr);
        if (0 == idx % 16) {
            fprintf(stderr, "%s\n", ascii);
            if (idx >= len) break;
        }
    }
}

void hexdump_at(void *ptr, size_t len) { hexdump_addr(ptr, len, ptr); }
void hexdump(void *ptr, size_t len) { hexdump_addr(ptr, len, 0); }

void
debug_print_gdb(void *ptr, char *type_name)
{
    extern const char *__progname;
    char cmd[BUFSIZ];
    fprintf(stderr, "ADDRESS: %p\n", ptr);
    //sprintf(cmd, "gdb -batch -ex 'p (struct %s)%p' /proc/self/exe %d", type_name, ptr, getpid());
    sprintf(cmd, "gdb -batch -ex 'p *(struct %s *)%p' %s %d", type_name, ptr, __progname, getpid());
    //sprintf(cmd, "gdb %s %d", __progname, getpid());
    system(cmd);
}

void
debug_backtrace()
{
    extern const char *__progname;
    char cmd[BUFSIZ];
    sprintf(cmd, "gdb -batch -ex bt %s %d", __progname, getpid());
    system(cmd);
    _Exit(EXIT_FAILURE);
}

#if 0
struct stack_frame {
    struct stack_frame *prev;
    void *return_address;
} __attribute__((packed));

//__attribute__((always_inline))
struct stack_frame *
get_call_stack(void) {
    /* x86/gcc specific: this tells gcc that the fp
     * variable should be an alias to the %ebp register
     * whick keeps the frame pointer */
    struct stack_frame *fp;

    //__asm__ volatile ("movl %%ebp, %[fp]" : [fp] "=r" (fp));
    __asm__ volatile ("movq %%rbp, %[fp]" : [fp] "=r" (fp));

    return fp;
}
#endif

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

//#include <dwarf.h>
#define DW_TAG_array_type               0x01
//#define DW_TAG_class_type               0x02
//#define DW_TAG_entry_point              0x03
//#define DW_TAG_enumeration_type         0x04
//#define DW_TAG_formal_parameter         0x05
//#define DW_TAG_imported_declaration     0x08
//#define DW_TAG_label                    0x0a
//#define DW_TAG_lexical_block            0x0b
#define DW_TAG_member                   0x0d
#define DW_TAG_pointer_type             0x0f
//#define DW_TAG_reference_type           0x10
#define DW_TAG_compile_unit             0x11
//#define DW_TAG_string_type              0x12
#define DW_TAG_structure_type           0x13
//#define DW_TAG_subroutine_type          0x15
#define DW_TAG_typedef                  0x16
//#define DW_TAG_union_type               0x17
//#define DW_TAG_unspecified_parameters   0x18
//#define DW_TAG_variant                  0x19
//#define DW_TAG_common_block             0x1a
//#define DW_TAG_common_inclusion         0x1b
//#define DW_TAG_inheritance              0x1c
//#define DW_TAG_inlined_subroutine       0x1d
//#define DW_TAG_module                   0x1e
//#define DW_TAG_ptr_to_member_type       0x1f
//#define DW_TAG_set_type                 0x20
#define DW_TAG_subrange_type            0x21
//#define DW_TAG_with_stmt                0x22
//#define DW_TAG_access_declaration       0x23
#define DW_TAG_base_type                0x24
//#define DW_TAG_catch_block              0x25
//#define DW_TAG_const_type               0x26
//#define DW_TAG_constant                 0x27
//#define DW_TAG_enumerator               0x28
//#define DW_TAG_file_type                0x29
//#define DW_TAG_friend                   0x2a
//#define DW_TAG_namelist                 0x2b
//        /*  Early releases of this header had the following
//            misspelled with a trailing 's' */
//#define DW_TAG_namelist_item            0x2c /* DWARF3/2 spelling */
//#define DW_TAG_namelist_items           0x2c /* SGI misspelling/typo */
//#define DW_TAG_packed_type              0x2d
#define DW_TAG_subprogram               0x2e
//        /*  The DWARF2 document had two spellings of the following
//            two TAGs, DWARF3 specifies the longer spelling. */
//#define DW_TAG_template_type_parameter  0x2f /* DWARF3/2 spelling*/
//#define DW_TAG_template_type_param      0x2f /* DWARF2   spelling*/
//#define DW_TAG_template_value_parameter 0x30 /* DWARF3/2 spelling*/
//#define DW_TAG_template_value_param     0x30 /* DWARF2   spelling*/
//#define DW_TAG_thrown_type              0x31
//#define DW_TAG_try_block                0x32
//#define DW_TAG_variant_part             0x33
#define DW_TAG_variable                 0x34
//#define DW_TAG_volatile_type            0x35
//#define DW_TAG_dwarf_procedure          0x36  /* DWARF3 */
//#define DW_TAG_restrict_type            0x37  /* DWARF3 */
//#define DW_TAG_interface_type           0x38  /* DWARF3 */
//#define DW_TAG_namespace                0x39  /* DWARF3 */
//#define DW_TAG_imported_module          0x3a  /* DWARF3 */
//#define DW_TAG_unspecified_type         0x3b  /* DWARF3 */
//#define DW_TAG_partial_unit             0x3c  /* DWARF3 */
//#define DW_TAG_imported_unit            0x3d  /* DWARF3 */
//        /*  Do not use DW_TAG_mutable_type */
//#define DW_TAG_mutable_type 0x3e /* Withdrawn from DWARF3 by DWARF3f. */
//#define DW_TAG_condition                0x3f  /* DWARF3f */
//#define DW_TAG_shared_type              0x40  /* DWARF3f */
//#define DW_TAG_type_unit                0x41  /* DWARF4 */
//#define DW_TAG_rvalue_reference_type    0x42  /* DWARF4 */
//#define DW_TAG_template_alias           0x43  /* DWARF4 */
//#define DW_TAG_lo_user                  0x4080
//
//#define DW_TAG_MIPS_loop                0x4081
//
///* HP extensions: ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz  */
//#define DW_TAG_HP_array_descriptor      0x4090 /* HP */
//
///* GNU extensions.  The first 3 missing the GNU_. */
//#define DW_TAG_format_label             0x4101 /* GNU. Fortran. */
//#define DW_TAG_function_template        0x4102 /* GNU. For C++ */
//#define DW_TAG_class_template           0x4103 /* GNU. For C++ */
//#define DW_TAG_GNU_BINCL                0x4104 /* GNU */
//#define DW_TAG_GNU_EINCL                0x4105 /* GNU */
//
///* GNU extension. http://gcc.gnu.org/wiki/TemplateParmsDwarf */
//#define DW_TAG_GNU_template_template_parameter  0x4106 /* GNU */
//#define DW_TAG_GNU_template_template_param      0x4106 /* GNU */
//#define DW_TAG_GNU_template_parameter_pack      0x4107 /* GNU */
//#define DW_TAG_GNU_formal_parameter_pack        0x4108 /* GNU */
//
//#define DW_TAG_GNU_call_site                    0x4109 /* GNU */
//#define DW_TAG_GNU_call_site_parameter          0x410a /* GNU */
//
///* ALTIUM extensions */
//    /* DSP-C/Starcore __circ qualifier */
//#define DW_TAG_ALTIUM_circ_type         0x5101 /* ALTIUM */
//    /* Starcore __mwa_circ qualifier */ 
//#define DW_TAG_ALTIUM_mwa_circ_type     0x5102 /* ALTIUM */
//    /* Starcore __rev_carry qualifier */
//#define DW_TAG_ALTIUM_rev_carry_type    0x5103 /* ALTIUM */
//    /* M16 __rom qualifier */
//#define DW_TAG_ALTIUM_rom               0x5111 /* ALTIUM */
//
///* The following 3 are extensions to support UPC */
//#define DW_TAG_upc_shared_type          0x8765 /* UPC */
//#define DW_TAG_upc_strict_type          0x8766 /* UPC */
//#define DW_TAG_upc_relaxed_type         0x8767 /* UPC */
//
///* PGI (STMicroelectronics) extensions. */
//#define DW_TAG_PGI_kanji_type           0xa000 /* PGI */
//#define DW_TAG_PGI_interface_block      0xa020 /* PGI */
///* The following are SUN extensions */
//#define DW_TAG_SUN_function_template    0x4201 /* SUN */
//#define DW_TAG_SUN_class_template       0x4202 /* SUN */
//#define DW_TAG_SUN_struct_template      0x4203 /* SUN */
//#define DW_TAG_SUN_union_template       0x4204 /* SUN */
//#define DW_TAG_SUN_indirect_inheritance 0x4205 /* SUN */
//#define DW_TAG_SUN_codeflags            0x4206 /* SUN */
//#define DW_TAG_SUN_memop_info           0x4207 /* SUN */
//#define DW_TAG_SUN_omp_child_func       0x4208 /* SUN */
//#define DW_TAG_SUN_rtti_descriptor      0x4209 /* SUN */
//#define DW_TAG_SUN_dtor_info            0x420a /* SUN */
//#define DW_TAG_SUN_dtor                 0x420b /* SUN */
//#define DW_TAG_SUN_f90_interface        0x420c /* SUN */
//#define DW_TAG_SUN_fortran_vax_structure 0x420d /* SUN */
//#define DW_TAG_SUN_hi                   0x42ff /* SUN */
//    
//
//#define DW_TAG_hi_user                  0xffff

#define DW_children_no                  0
#define DW_children_yes                 1

#define DW_FORM_addr                    0x01
#define DW_FORM_block2                  0x03
#define DW_FORM_block4                  0x04
#define DW_FORM_data2                   0x05
#define DW_FORM_data4                   0x06
#define DW_FORM_data8                   0x07
#define DW_FORM_string                  0x08
#define DW_FORM_block                   0x09
#define DW_FORM_block1                  0x0a
#define DW_FORM_data1                   0x0b
#define DW_FORM_flag                    0x0c
#define DW_FORM_sdata                   0x0d
#define DW_FORM_strp                    0x0e
#define DW_FORM_udata                   0x0f
#define DW_FORM_ref_addr                0x10
#define DW_FORM_ref1                    0x11
#define DW_FORM_ref2                    0x12
#define DW_FORM_ref4                    0x13
#define DW_FORM_ref8                    0x14
#define DW_FORM_ref_udata               0x15
#define DW_FORM_indirect                0x16
#define DW_FORM_sec_offset              0x17 /* DWARF4 */
#define DW_FORM_exprloc                 0x18 /* DWARF4 */
#define DW_FORM_flag_present            0x19 /* DWARF4 */
/* 0x1a thru 0x1f were left unused accidentally. Reserved for future use. */
#define DW_FORM_ref_sig8                0x20 /* DWARF4 */

//#define DW_AT_sibling                           0x01
//#define DW_AT_location                          0x02
#define DW_AT_name                              0x03
//#define DW_AT_ordering                          0x09
//#define DW_AT_subscr_data                       0x0a
#define DW_AT_byte_size                         0x0b
//#define DW_AT_bit_offset                        0x0c
//#define DW_AT_bit_size                          0x0d
//#define DW_AT_element_list                      0x0f
//#define DW_AT_stmt_list                         0x10
//#define DW_AT_low_pc                            0x11
//#define DW_AT_high_pc                           0x12
//#define DW_AT_language                          0x13
//#define DW_AT_member                            0x14
//#define DW_AT_discr                             0x15
//#define DW_AT_discr_value                       0x16
//#define DW_AT_visibility                        0x17
//#define DW_AT_import                            0x18
//#define DW_AT_string_length                     0x19
//#define DW_AT_common_reference                  0x1a
//#define DW_AT_comp_dir                          0x1b
//#define DW_AT_const_value                       0x1c
//#define DW_AT_containing_type                   0x1d
//#define DW_AT_default_value                     0x1e
//#define DW_AT_inline                            0x20
//#define DW_AT_is_optional                       0x21
//#define DW_AT_lower_bound                       0x22
//#define DW_AT_producer                          0x25
//#define DW_AT_prototyped                        0x27
//#define DW_AT_return_addr                       0x2a
//#define DW_AT_start_scope                       0x2c
//#define DW_AT_bit_stride                        0x2e /* DWARF3 name */
//#define DW_AT_stride_size                       0x2e /* DWARF2 name */
#define DW_AT_upper_bound                       0x2f
//#define DW_AT_abstract_origin                   0x31
//#define DW_AT_accessibility                     0x32
//#define DW_AT_address_class                     0x33
//#define DW_AT_artificial                        0x34
//#define DW_AT_base_types                        0x35
//#define DW_AT_calling_convention                0x36
//#define DW_AT_count                             0x37
#define DW_AT_data_member_location              0x38
//#define DW_AT_decl_column                       0x39
//#define DW_AT_decl_file                         0x3a
//#define DW_AT_decl_line                         0x3b
//#define DW_AT_declaration                       0x3c
//#define DW_AT_discr_list                        0x3d
#define DW_AT_encoding                          0x3e
//#define DW_AT_external                          0x3f
//#define DW_AT_frame_base                        0x40
//#define DW_AT_friend                            0x41
//#define DW_AT_identifier_case                   0x42
//#define DW_AT_macro_info                        0x43
//#define DW_AT_namelist_item                     0x44
//#define DW_AT_priority                          0x45
//#define DW_AT_segment                           0x46
//#define DW_AT_specification                     0x47
//#define DW_AT_static_link                       0x48
#define DW_AT_type                              0x49
//#define DW_AT_use_location                      0x4a
//#define DW_AT_variable_parameter                0x4b
//#define DW_AT_virtuality                        0x4c
//#define DW_AT_vtable_elem_location              0x4d
//#define DW_AT_allocated                         0x4e /* DWARF3 */
//#define DW_AT_associated                        0x4f /* DWARF3 */
//#define DW_AT_data_location                     0x50 /* DWARF3 */
//#define DW_AT_byte_stride                       0x51 /* DWARF3f */
//#define DW_AT_stride                            0x51 /* DWARF3 (do not use) */
//#define DW_AT_entry_pc                          0x52 /* DWARF3 */
//#define DW_AT_use_UTF8                          0x53 /* DWARF3 */
//#define DW_AT_extension                         0x54 /* DWARF3 */
//#define DW_AT_ranges                            0x55 /* DWARF3 */
//#define DW_AT_trampoline                        0x56 /* DWARF3 */
//#define DW_AT_call_column                       0x57 /* DWARF3 */
//#define DW_AT_call_file                         0x58 /* DWARF3 */
//#define DW_AT_call_line                         0x59 /* DWARF3 */
//#define DW_AT_description                       0x5a /* DWARF3 */
//#define DW_AT_binary_scale                      0x5b /* DWARF3f */
//#define DW_AT_decimal_scale                     0x5c /* DWARF3f */
//#define DW_AT_small                             0x5d /* DWARF3f */
//#define DW_AT_decimal_sign                      0x5e /* DWARF3f */
//#define DW_AT_digit_count                       0x5f /* DWARF3f */
//#define DW_AT_picture_string                    0x60 /* DWARF3f */
//#define DW_AT_mutable                           0x61 /* DWARF3f */
//#define DW_AT_threads_scaled                    0x62 /* DWARF3f */
//#define DW_AT_explicit                          0x63 /* DWARF3f */
//#define DW_AT_object_pointer                    0x64 /* DWARF3f */
//#define DW_AT_endianity                         0x65 /* DWARF3f */
//#define DW_AT_elemental                         0x66 /* DWARF3f */
//#define DW_AT_pure                              0x67 /* DWARF3f */
//#define DW_AT_recursive                         0x68 /* DWARF3f */
//#define DW_AT_signature                         0x69 /* DWARF4 */
//#define DW_AT_main_subprogram                   0x6a /* DWARF4 */
//#define DW_AT_data_bit_offset                   0x6b /* DWARF4 */
//#define DW_AT_const_expr                        0x6c /* DWARF4 */
//#define DW_AT_enum_class                        0x6d /* DWARF4 */
//#define DW_AT_linkage_name                      0x6e /* DWARF4 */
//
///* In extensions, we attempt to include the vendor extension
//   in the name even when the vendor leaves it out. */
//
///* HP extensions. */
//#define DW_AT_HP_block_index                    0x2000  /* HP */
//
///* Follows extension so dwarfdump prints the most-likely-useful name. */
//#define DW_AT_lo_user                           0x2000
//
//#define DW_AT_MIPS_fde                          0x2001 /* MIPS/SGI */
//#define DW_AT_MIPS_loop_begin                   0x2002 /* MIPS/SGI */
//#define DW_AT_MIPS_tail_loop_begin              0x2003 /* MIPS/SGI */
//#define DW_AT_MIPS_epilog_begin                 0x2004 /* MIPS/SGI */
//#define DW_AT_MIPS_loop_unroll_factor           0x2005 /* MIPS/SGI */
//#define DW_AT_MIPS_software_pipeline_depth      0x2006 /* MIPS/SGI */
//#define DW_AT_MIPS_linkage_name                 0x2007 /* MIPS/SGI, GNU, and others.*/
//#define DW_AT_MIPS_stride                       0x2008 /* MIPS/SGI */
//#define DW_AT_MIPS_abstract_name                0x2009 /* MIPS/SGI */
//#define DW_AT_MIPS_clone_origin                 0x200a /* MIPS/SGI */
//#define DW_AT_MIPS_has_inlines                  0x200b /* MIPS/SGI */
//#define DW_AT_MIPS_stride_byte                  0x200c /* MIPS/SGI */
//#define DW_AT_MIPS_stride_elem                  0x200d /* MIPS/SGI */
//#define DW_AT_MIPS_ptr_dopetype                 0x200e /* MIPS/SGI */
//#define DW_AT_MIPS_allocatable_dopetype         0x200f /* MIPS/SGI */
//#define DW_AT_MIPS_assumed_shape_dopetype       0x2010 /* MIPS/SGI */
//#define DW_AT_MIPS_assumed_size                 0x2011 /* MIPS/SGI */
//
///* HP extensions. */
//#define DW_AT_HP_unmodifiable                   0x2001 /* conflict: MIPS */
//#define DW_AT_HP_actuals_stmt_list              0x2010 /* conflict: MIPS */
//#define DW_AT_HP_proc_per_section               0x2011 /* conflict: MIPS */
//#define DW_AT_HP_raw_data_ptr                   0x2012 /* HP */
//#define DW_AT_HP_pass_by_reference              0x2013 /* HP */
//#define DW_AT_HP_opt_level                      0x2014 /* HP */
//#define DW_AT_HP_prof_version_id                0x2015 /* HP */
//#define DW_AT_HP_opt_flags                      0x2016 /* HP */
//#define DW_AT_HP_cold_region_low_pc             0x2017 /* HP */
//#define DW_AT_HP_cold_region_high_pc            0x2018 /* HP */
//#define DW_AT_HP_all_variables_modifiable       0x2019 /* HP */
//#define DW_AT_HP_linkage_name                   0x201a /* HP */
//#define DW_AT_HP_prof_flags                     0x201b /* HP */
//
//#define DW_AT_CPQ_discontig_ranges              0x2001 /* COMPAQ/HP */
//#define DW_AT_CPQ_semantic_events               0x2002 /* COMPAQ/HP */
//#define DW_AT_CPQ_split_lifetimes_var           0x2003 /* COMPAQ/HP */
//#define DW_AT_CPQ_split_lifetimes_rtn           0x2004 /* COMPAQ/HP */
//#define DW_AT_CPQ_prologue_length               0x2005 /* COMPAQ/HP */
//
//#define DW_AT_INTEL_other_endian                0x2026 /* Intel, 1 if byte swapped. */
//
///* GNU extensions. */
//#define DW_AT_sf_names                          0x2101 /* GNU */
//#define DW_AT_src_info                          0x2102 /* GNU */
//#define DW_AT_mac_info                          0x2103 /* GNU */
//#define DW_AT_src_coords                        0x2104 /* GNU */
//#define DW_AT_body_begin                        0x2105 /* GNU */
//#define DW_AT_body_end                          0x2106 /* GNU */
//#define DW_AT_GNU_vector                        0x2107 /* GNU */
//
///*  Thread safety, see http://gcc.gnu.org/wiki/ThreadSafetyAnnotation .  */
///*  The values here are from gcc-4.6.2 include/dwarf2.h.  The
//    values are not given on the web page at all, nor on web pages
//    it refers to. */
//#define DW_AT_GNU_guarded_by                    0x2108 /* GNU */
//#define DW_AT_GNU_pt_guarded_by                 0x2109 /* GNU */
//#define DW_AT_GNU_guarded                       0x210a /* GNU */
//#define DW_AT_GNU_pt_guarded                    0x210b /* GNU */
//#define DW_AT_GNU_locks_excluded                0x210c /* GNU */
//#define DW_AT_GNU_exclusive_locks_required      0x210d /* GNU */
//#define DW_AT_GNU_shared_locks_required         0x210e /* GNU */
//
///* See http://gcc.gnu.org/wiki/DwarfSeparateTypeInfo */
//#define DW_AT_GNU_odr_signature                 0x210f /* GNU */
//
///*  See  See http://gcc.gnu.org/wiki/TemplateParmsDwarf */
///*  The value here is from gcc-4.6.2 include/dwarf2.h.  The value is
//    not consistent with the web page as of December 2011. */
//#define DW_AT_GNU_template_name                 0x2110 /* GNU */
///*  The GNU call site extension.
//    See http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open .  */
//#define DW_AT_GNU_call_site_value               0x2111 /* GNU */
//#define DW_AT_GNU_call_site_data_value          0x2112 /* GNU */
//#define DW_AT_GNU_call_site_target              0x2113 /* GNU */
//#define DW_AT_GNU_call_site_target_clobbered    0x2114 /* GNU */
//#define DW_AT_GNU_tail_call                     0x2115 /* GNU */
//#define DW_AT_GNU_all_tail_call_sites           0x2116 /* GNU */
//#define DW_AT_GNU_all_call_sites                0x2117 /* GNU */
//#define DW_AT_GNU_all_source_call_sites         0x2118 /* GNU */
//
//
//
///* ALTIUM extension: ALTIUM Compliant location lists (flag) */
//#define DW_AT_ALTIUM_loclist    0x2300          /* ALTIUM  */
//
///* Sun extensions */
//#define DW_AT_SUN_template                      0x2201 /* SUN */
//#define DW_AT_VMS_rtnbeg_pd_address             0x2201 /* VMS */
//#define DW_AT_SUN_alignment                     0x2202 /* SUN */
//#define DW_AT_SUN_vtable                        0x2203 /* SUN */
//#define DW_AT_SUN_count_guarantee               0x2204 /* SUN */
//#define DW_AT_SUN_command_line                  0x2205 /* SUN */
//#define DW_AT_SUN_vbase                         0x2206 /* SUN */
//#define DW_AT_SUN_compile_options               0x2207 /* SUN */
//#define DW_AT_SUN_language                      0x2208 /* SUN */
//#define DW_AT_SUN_browser_file                  0x2209 /* SUN */
//#define DW_AT_SUN_vtable_abi                    0x2210 /* SUN */
//#define DW_AT_SUN_func_offsets                  0x2211 /* SUN */
//#define DW_AT_SUN_cf_kind                       0x2212 /* SUN */
//#define DW_AT_SUN_vtable_index                  0x2213 /* SUN */
//#define DW_AT_SUN_omp_tpriv_addr                0x2214 /* SUN */
//#define DW_AT_SUN_omp_child_func                0x2215 /* SUN */
//#define DW_AT_SUN_func_offset                   0x2216 /* SUN */
//#define DW_AT_SUN_memop_type_ref                0x2217 /* SUN */
//#define DW_AT_SUN_profile_id                    0x2218 /* SUN */
//#define DW_AT_SUN_memop_signature               0x2219 /* SUN */
//#define DW_AT_SUN_obj_dir                       0x2220 /* SUN */
//#define DW_AT_SUN_obj_file                      0x2221 /* SUN */
//#define DW_AT_SUN_original_name                 0x2222 /* SUN */
//#define DW_AT_SUN_hwcprof_signature             0x2223 /* SUN */
//#define DW_AT_SUN_amd64_parmdump                0x2224 /* SUN */
//#define DW_AT_SUN_part_link_name                0x2225 /* SUN */
//#define DW_AT_SUN_link_name                     0x2226 /* SUN */
//#define DW_AT_SUN_pass_with_const               0x2227 /* SUN */
//#define DW_AT_SUN_return_with_const             0x2228 /* SUN */
//#define DW_AT_SUN_import_by_name                0x2229 /* SUN */
//#define DW_AT_SUN_f90_pointer                   0x222a /* SUN */
//#define DW_AT_SUN_pass_by_ref                   0x222b /* SUN */
//#define DW_AT_SUN_f90_allocatable               0x222c /* SUN */
//#define DW_AT_SUN_f90_assumed_shape_array       0x222d /* SUN */
//#define DW_AT_SUN_c_vla                         0x222e /* SUN */
//#define DW_AT_SUN_return_value_ptr              0x2230 /* SUN */
//#define DW_AT_SUN_dtor_start                    0x2231 /* SUN */
//#define DW_AT_SUN_dtor_length                   0x2232 /* SUN */
//#define DW_AT_SUN_dtor_state_initial            0x2233 /* SUN */
//#define DW_AT_SUN_dtor_state_final              0x2234 /* SUN */
//#define DW_AT_SUN_dtor_state_deltas             0x2235 /* SUN */
//#define DW_AT_SUN_import_by_lname               0x2236 /* SUN */
//#define DW_AT_SUN_f90_use_only                  0x2237 /* SUN */
//#define DW_AT_SUN_namelist_spec                 0x2238 /* SUN */
//#define DW_AT_SUN_is_omp_child_func             0x2239 /* SUN */
//#define DW_AT_SUN_fortran_main_alias            0x223a /* SUN */
//#define DW_AT_SUN_fortran_based                 0x223b /* SUN */
//
///*   See http://gcc.gnu.org/wiki/DW_AT_GNAT_descriptive_type .  */
//#define DW_AT_use_GNAT_descriptive_type         0x2301 /* GNAT */
//#define DW_AT_GNAT_descriptive_type             0x2302 /* GNAT */
//
///* UPC extension */
//#define DW_AT_upc_threads_scaled                0x3210 /* UPC */
//
///* PGI (STMicroelectronics) extensions. */
//#define DW_AT_PGI_lbase                         0x3a00 /* PGI. Block, constant, reference. This attribute is an ASTPLAB extension used to describe the array local base.  */
//#define DW_AT_PGI_soffset                       0x3a01  /* PGI. Block, constant, reference. ASTPLAB adds this attribute to describe the section offset, or the offset to the first element in the dimension. */ 
//#define DW_AT_PGI_lstride                       0x3a02  /* PGI. Block, constant, reference. ASTPLAB adds this attribute to describe the linear stride or the distance between elements in the dimension. */
//
///* There are two groups of Apple extensions here, it is
//   unclear what exactly is correct.  */
//#define DW_AT_APPLE_optimized                   0x3fe1 /* Apple */
//#define DW_AT_APPLE_flags                       0x3fe2 /* Apple */
//#define DW_AT_APPLE_isa                         0x3fe3 /* Apple */
//#define DW_AT_APPLE_block                       0x3fe4 /* Apple */
//#define DW_AT_APPLE_major_runtime_vers          0x3fe5 /* Apple */
//#define DW_AT_APPLE_runtime_class               0x3fe6 /* Apple */
//#define DW_AT_APPLE_omit_frame_ptr              0x3fe7 /* Apple */
//
///* Apple Extensions for closures  */
//#define DW_AT_APPLE_closure                     0x3fe4 /* Apple */
///* Apple Extensions for Objective-C runtime info */
//#define DW_AT_APPLE_major_runtime_vers          0x3fe5 /* Apple */
//#define DW_AT_APPLE_runtime_class               0x3fe6 /* Apple */
//
//
//#define DW_AT_hi_user                           0x3fff

//#define DW_ATE_address                  0x1
//#define DW_ATE_boolean                  0x2
//#define DW_ATE_complex_float            0x3
#define DW_ATE_float                    0x4
#define DW_ATE_signed                   0x5
#define DW_ATE_signed_char              0x6
#define DW_ATE_unsigned                 0x7
#define DW_ATE_unsigned_char            0x8
//#define DW_ATE_imaginary_float          0x9  /* DWARF3 */
//#define DW_ATE_packed_decimal           0xa  /* DWARF3f */
//#define DW_ATE_numeric_string           0xb  /* DWARF3f */
//#define DW_ATE_edited                   0xc  /* DWARF3f */
//#define DW_ATE_signed_fixed             0xd  /* DWARF3f */
//#define DW_ATE_unsigned_fixed           0xe  /* DWARF3f */
//#define DW_ATE_decimal_float            0xf  /* DWARF3f */
//
//
///* ALTIUM extensions. x80, x81 */
//#define DW_ATE_ALTIUM_fract           0x80 /* ALTIUM __fract type */
//
///* Follows extension so dwarfdump prints the most-likely-useful name. */
//#define DW_ATE_lo_user                  0x80
//
///* Shown here to help dwarfdump build script. */
//#define DW_ATE_ALTIUM_accum           0x81 /* ALTIUM __accum type */
//
///* HP Floating point extensions. */
//#define DW_ATE_HP_float80             0x80 /* (80 bit). HP */
//
//
//#define DW_ATE_HP_complex_float80     0x81 /* Complex (80 bit). HP  */
//#define DW_ATE_HP_float128            0x82 /* (128 bit). HP */
//#define DW_ATE_HP_complex_float128    0x83 /* Complex (128 bit). HP */
//#define DW_ATE_HP_floathpintel        0x84 /* (82 bit IA64). HP */
//#define DW_ATE_HP_imaginary_float80   0x85 /* HP */
//#define DW_ATE_HP_imaginary_float128  0x86 /* HP */
//
///* Sun extensions */
//#define DW_ATE_SUN_interval_float       0x91
//#define DW_ATE_SUN_imaginary_float      0x92 /* Obsolete: See DW_ATE_imaginary_float */
//
//#define DW_ATE_hi_user                  0xff

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


struct form_data {
    size_t len;
    union {
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        size_t integer;     // nicer
        void *addr;
    } data;
    //void *base_addr; // when ref_sig8
};

/* */
struct tag_attrib {
    uint16_t attrib;
    uint16_t form;
    //size_t offset;
    //size_t byte_size;
    struct tag_attrib *next;
};

struct abbrev {
    uint16_t tag;
    uint8_t index;
    uint8_t children;
    struct tag_attrib *tag_attrib;
    //struct abbrev *next;
};


static struct tag_attrib *
tag_attrib_new(uint16_t attrib, uint16_t form)
{
    struct tag_attrib *tag_attrib;

    tag_attrib = malloc(sizeof(struct tag_attrib));
    if (NULL == tag_attrib)
        return NULL;

    tag_attrib->attrib = attrib;
    tag_attrib->form = form;
    //tag_attrib->offset = 0;
    //tag_attrib->byte_size = 0;
    tag_attrib->next = NULL;

    return tag_attrib;
}

static struct abbrev *
abbrev_new(uint8_t index, uint16_t tag, uint8_t children)
{
    struct abbrev *abbrev;

    abbrev = malloc(sizeof(struct abbrev));
    if (NULL == abbrev)
        return NULL;

    abbrev->index = index;
    abbrev->tag = tag;
    abbrev->children = children;
    abbrev->tag_attrib = NULL;
    //abbrev->next = NULL;

    return abbrev;
}

static uint64_t
dwarf_parse_leb128(uint8_t **ptr)
{
    uint64_t result;
    uint64_t shift;
    uint8_t byte;

    result = 0;
    shift = 0;
    while (1) {
        byte = **ptr;
        (*ptr)++;
        result |= (byte & 0x7f) << shift;
        if (0 == (byte & 0x80))
            break;
        shift += 7;
    }

    return result;
}

// TODO: ??? doesnt return len, i.e. we may go out of bounds when using...
static int
dwarf_abbrev_parse(struct elf_ctx *elf_ctx)
{
    uint8_t *ptr = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_abbrev_sh->sh_offset;
    size_t abbrev_array_len = 0;

    uint8_t index;
    //void *start_ptr = ptr;
    struct tag_attrib **next_ptr;
    struct tag_attrib *tag_attrib;
    struct abbrev *abbrev;
    uint8_t children;
    uint16_t tag;
    void *ret_ptr;
    uint16_t attrib;
    uint16_t form;

    // init abbrev_array
    abbrev_array_len = 128;
    elf_ctx->abbrev_array = calloc(abbrev_array_len, sizeof(void *));
    if (NULL == elf_ctx->abbrev_array)
        return -1;


    index = 1;
    while (1) {
        if (index != ptr[0]) {
            // 0 == end of segments
            if (0 == ptr[0])
                return 0;

            fprintf(stderr, "[E] index mismatch (%x != %x\n", index, ptr[0]);
            return -1;
        }
        ptr++;

        // TAG
        tag = dwarf_parse_leb128(&ptr);

        // DW_CHILDREN
        children = *ptr++;

        // create abbrev struct
        abbrev = abbrev_new(index, tag, children);
        if (NULL == abbrev)
            return -1;            // TODO: should clean up first!
        if (index >= abbrev_array_len) {
            ret_ptr = realloc(elf_ctx->abbrev_array, 2 * abbrev_array_len * sizeof(void *));
            if (NULL == ret_ptr) {
                abbrev_array_len = 0;
                free(elf_ctx->abbrev_array);                                                                    // free
                elf_ctx->abbrev_array = NULL;
                return -1;
            }
            // clear upper half
            memset(elf_ctx->abbrev_array + abbrev_array_len * sizeof(void *), 0, abbrev_array_len);
            abbrev_array_len *= 2;
        }
        elf_ctx->abbrev_array[index] = abbrev;
        next_ptr = &(abbrev->tag_attrib);

        while (1) {
            attrib = dwarf_parse_leb128(&ptr);
            form = dwarf_parse_leb128(&ptr);

            if (0 == attrib && 0 == form)
                break;

            tag_attrib = tag_attrib_new(attrib, form);
            if (NULL == tag_attrib) {
                return -1;
            }
            *next_ptr = tag_attrib;
            next_ptr = &(tag_attrib->next);
        }

        index++;
    }
    return 0;
}

static uint8_t
dwarf_get_index(void **addr)
{
    uint8_t index;

    index = **(uint8_t **)addr;
    (*addr)++;
    return index;
}


TAILQ_HEAD(type_cache_head, type_cache) type_cache_head;
struct type_cache {
    struct type *type;
    void *addr;     // address in compact structure (DWARF_INFO/DWARF_TYPES)

    //struct type_cache *next;
    TAILQ_ENTRY(type_cache) next;
};

static struct type_cache *
type_cache_new(struct type *type, void *addr)
{
    struct type_cache *type_cache;

    type_cache = malloc(sizeof(struct type_cache));
    if (NULL == type_cache)
        return NULL;

    type_cache->type = type;
    type_cache->addr = addr;

    TAILQ_INSERT_TAIL(&type_cache_head, type_cache, next);

    return type_cache;
}

static struct type *
type_cache_get(void *addr)
{
    struct type_cache *type_cache;

    TAILQ_FOREACH(type_cache, &type_cache_head, next) {
        if (addr == type_cache->addr)
            return type_cache->type;
    }

    return NULL;
}

TAILQ_HEAD(type_head, type);
// will also include member tags
struct type {
    uint16_t tag;
    char *name;
    struct type *type;
    size_t offset;
    size_t byte_size;
    size_t upper_bound;
    //int type;       // int, float, pointer, struct, ...

    uint8_t encoding;
    //struct type *sibling;

    //TAILQ_HEAD(type_head, type) siblings_head;
    struct type_head child_head;     // will not redefine struct head

    //struct type *next;
    TAILQ_ENTRY(type) next;
};

static struct type *
type_new(void *addr)
{
    struct type *type;
    struct type_cache *type_cache;

    type = malloc(sizeof(struct type));
    if (NULL == type)
        goto err_malloc;

    //memset(type, 0, sizeof(struct type));
    type->type = NULL;
    type->tag = 0;
    type->name = NULL;
    type->offset = 0;
    type->byte_size = 0;
    type->upper_bound = 0;
    type->encoding = 0;

    TAILQ_INIT(&type->child_head);
    //type->next = NULL;

    type_cache = type_cache_new(type, addr);
    if (NULL == type_cache)
        goto err;

    //TAILQ_INSERT_TAIL(&type_head, type, next);
    return type;

err:
    free(type);
err_malloc:
    return NULL;
}

static void
type_remove_all(void)
{
    struct type_cache *type_cache, *type_cache_tmp;

    TAILQ_FOREACH_SAFE(type_cache, &type_cache_head, next, type_cache_tmp) {
        free(type_cache->type);                                                                                 // free

        TAILQ_REMOVE(&type_cache_head, type_cache, next);
        free(type_cache);
    }
}

static void *
dwarf_types_type_unit_get_next(struct elf_ctx *elf_ctx, struct dwarf_types_unit_header *type_unit)
{
    void *start_ptr = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_types_sh->sh_offset;
    size_t len;
    void *ptr;

    if (NULL == type_unit) {
        return start_ptr;
    }

    len = elf_ctx->dwarf_debug_types_sh->sh_size;
    ptr = type_unit;
    if ((size_t)(ptr - start_ptr) < len)
        return (char*)type_unit + sizeof(type_unit->length) + type_unit->length;
    else
        return NULL;
}

static struct dwarf_types_unit_header *
dwarf_types_get_type_unit(struct elf_ctx *elf_ctx, uint64_t signature)
{
    struct dwarf_types_unit_header *type_unit;

    type_unit = NULL;
    while (NULL != (type_unit = dwarf_types_type_unit_get_next(elf_ctx, type_unit))) {
        if (signature == type_unit->signature)
            return type_unit;
    }

    return NULL;
}

static void *
dwarf_get_base_addr(struct elf_ctx *elf_ctx, void *addr)
{
    struct dwarf_types_unit_header *type_unit_header;
    struct dwarf_compilation_unit_header *comp_unit_header;

    comp_unit_header = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_info_sh->sh_offset;
    if (addr >= (void *)comp_unit_header &&
        addr < (void *)comp_unit_header + comp_unit_header->length + sizeof(comp_unit_header->length))
    {
        return comp_unit_header;
    }

    type_unit_header = NULL;
    while (NULL != (type_unit_header = dwarf_types_type_unit_get_next(elf_ctx, type_unit_header))) {
        if (addr >= (void *)type_unit_header &&
            addr < (void *)type_unit_header + type_unit_header->length + sizeof(type_unit_header->length))
        {
            return type_unit_header;
        }
    }

    // not found
    fprintf(stderr, "[E] base_addr error!!!\n");
    return NULL;
}

static struct form_data *
dwarf_form_parse(struct elf_ctx *elf_ctx, struct tag_attrib *tag_attrib, void **ret_ptr)
{
    void *ptr = *ret_ptr;
    static struct form_data data; // return value, must copy data before called again!
    size_t len;
    uint64_t signature;
    struct dwarf_types_unit_header *type_unit;

    memset(&data, 0, sizeof(data));

    switch (tag_attrib->form) {
    case DW_FORM_addr:
        data.data.addr = *(void **)ptr;
        data.len = sizeof(void *);
        ptr += data.len;
        break;
    case DW_FORM_block2:
        len = *(uint16_t *)ptr;
        ptr += sizeof(uint16_t);
        data.data.addr = ptr;
        data.len = len;
        ptr += len;
        break;
    case DW_FORM_block4:
        len = *(uint32_t *)ptr;
        ptr += sizeof(uint32_t);
        data.data.addr = ptr;
        data.len = len;
        ptr += len;
        break;
    case DW_FORM_data2:
        data.data.uint16 = *(uint16_t *)ptr;
        data.len = sizeof(uint16_t);
        ptr += data.len;
        break;
    case DW_FORM_data4:
        data.data.uint32 = *(uint32_t *)ptr;
        data.len = sizeof(uint32_t);
        ptr += data.len;
        break;
    case DW_FORM_data8:
        data.data.uint64 = *(uint64_t *)ptr;
        data.len = sizeof(uint64_t);
        ptr += data.len;
        break;
    case DW_FORM_string:
        data.data.addr = ptr;
        data.len = strlen(ptr) + 1;
        ptr += data.len;
        //printf("STRING: \"%s\"\n", (char *)data.addr);
        break;
    case DW_FORM_block:
        //printf("BLOCK NOT IMPLEMENTED\n");
        data.len = dwarf_parse_leb128((uint8_t **)ret_ptr);
        data.data.addr = ptr;
        ptr += data.len;
        break;
    case DW_FORM_block1:
        //printf("BLOCK1 NOT IMPLEMENTED\n");
        data.len = *(uint8_t *)ptr;
        ptr += 1;
        data.data.addr = ptr;
        ptr += data.len;
        break;
    case DW_FORM_data1:
        data.data.uint8 = *(uint8_t *)ptr;
        data.len = 1;
        ptr += data.len;
        break;
    case DW_FORM_flag:
        fprintf(stderr, "[E] flag not implemented\n");
        hexdump(ptr, 16);
        exit(EXIT_FAILURE);
        break;
    case DW_FORM_sdata:
        data.data.uint64 = dwarf_parse_leb128((uint8_t **)&ptr);
        data.len = sizeof(uint64_t);       // assume biggest int
        break;
    case DW_FORM_strp:
        data.data.addr = elf_ctx->dwarf_debug_str + *(uint32_t *)ptr;
        ptr += 4;
        data.len = strlen(data.data.addr) + 1;
        //printf("STRP: \"%s\"\n", (char *)data.addr);
        break;
    case DW_FORM_udata:
        fprintf(stderr, "[E] udata not implemented\n");
        hexdump(ptr, 16);
        exit(EXIT_FAILURE);
        break;
    case DW_FORM_ref_addr:
        fprintf(stderr, "[E] ref addr not implemented\n");
        hexdump(ptr, 16);
        exit(EXIT_FAILURE);
        break;
    case DW_FORM_ref1:
        data.data.addr = dwarf_get_base_addr(elf_ctx, ptr) + *(uint8_t *)ptr;
        data.len = sizeof(uint8_t);
        ptr += data.len;
        break;
    case DW_FORM_ref2:
        data.data.addr = dwarf_get_base_addr(elf_ctx, ptr) + *(uint16_t *)ptr;
        data.len = sizeof(uint16_t);
        ptr += data.len;
        break;
    case DW_FORM_ref4:
        data.data.addr = dwarf_get_base_addr(elf_ctx, ptr) + *(uint32_t *)ptr;
        data.len = sizeof(uint32_t);
        ptr += data.len;
        break;
    case DW_FORM_ref8:
        data.data.addr = dwarf_get_base_addr(elf_ctx, ptr) + *(uint64_t *)ptr;
        data.len = sizeof(uint64_t);
        ptr += data.len;
        break;
    case DW_FORM_ref_udata:
        fprintf(stderr, "[E] ref udata not implemented\n");
        hexdump(ptr, 16);
        exit(EXIT_FAILURE);
        break;
    case DW_FORM_indirect:
        fprintf(stderr, "[E] indirect not implemented\n");
        hexdump(ptr, 16);
        exit(EXIT_FAILURE);
        break;
    case DW_FORM_sec_offset:
        data.data.uint32 = *(uint32_t *)ptr;
        data.len = sizeof(uint32_t);
        ptr += data.len;
        break;
    case DW_FORM_exprloc:
        data.len = *(uint8_t *)ptr;
        ptr += sizeof(uint8_t);
        data.data.addr = ptr;
        ptr += data.len;
        break;
    case DW_FORM_flag_present:
        data.data.integer = 1;  // flag is implicit true
        data.len = 0;
        break;
    case DW_FORM_ref_sig8:
        signature = *(uint64_t *)ptr;
        data.data.addr = NULL;
        type_unit = dwarf_types_get_type_unit(elf_ctx, signature);
        if (NULL == type_unit)
            goto quit;
        //data.base_addr = type_unit;     // ref_sig8 is referencing into .debug_types section
        data.data.addr = (void *)type_unit + type_unit->offset;
        ptr += sizeof(uint64_t);
        data.len = 0;       // TODO: I dont know???
        break;
    default:
        hexdump(ptr, 32);
        break;
    }

    //fprintf(stderr, "data: %lx\n", data.uint64);

    *ret_ptr = ptr;
    return &data;

quit:
    fprintf(stderr, "[E] error in elf!\n");
    hexdump(ptr, 16);
    exit(EXIT_FAILURE);
}

static void *
dwarf_info_get_variable_type_in_tag_list(struct elf_ctx *elf_ctx, void **comp_unit,
                                         const char *function_name, const char *variable_name)
{
    uint8_t index;
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;
    //struct dwarf_compilation_unit_header *comp_unit_header;
    struct form_data *data;
    void *type_addr;

    type_addr = NULL;
    //comp_unit_header = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_info_sh->sh_offset;
    index = dwarf_get_index(comp_unit);
    while (0 != index) {
        abbrev = elf_ctx->abbrev_array[index];

        tag_attrib = abbrev->tag_attrib;
        while (NULL != tag_attrib) {
            data = dwarf_form_parse(elf_ctx, tag_attrib, comp_unit);
            if (NULL != function_name &&
                DW_TAG_subprogram == abbrev->tag &&
                DW_AT_name == tag_attrib->attrib &&
                0 == strcmp(function_name, data->data.addr))
            {
                 function_name = NULL;
            }

            // trust that DW_AT_name is before DW_AT_type
            if (NULL == function_name &&
                NULL != variable_name &&
                DW_TAG_variable == abbrev->tag &&
                DW_AT_name == tag_attrib->attrib &&
                0 == strcmp(variable_name, data->data.addr))
            {
                variable_name = NULL;
            }

            if (NULL == function_name &&
                NULL == variable_name &&
                DW_TAG_variable == abbrev->tag &&
                DW_AT_type == tag_attrib->attrib)
            {
                type_addr = data->data.addr;
                return type_addr;
            }

            tag_attrib = tag_attrib->next;
        }

        if (DW_children_yes == abbrev->children) {
            type_addr = dwarf_info_get_variable_type_in_tag_list(elf_ctx, comp_unit, function_name, variable_name);
            if (NULL != type_addr) {
                return type_addr;
            }
        }

        index = dwarf_get_index(comp_unit);
    }

    return NULL;
}

static void *
dwarf_info_get_variable_type(struct elf_ctx *elf_ctx, char *function_name, char *variable_name)
{
    struct dwarf_compilation_unit_header *comp_unit_header;
    void *comp_unit;
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;
    uint8_t index;
    void *type_addr;

    comp_unit_header = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_info_sh->sh_offset;
    //debug_print_gdb(comp_unit_header, "dwarf_compilation_unit_header");
    //comp_unit = (void *)comp_unit_header + sizeof(comp_unit_header->length) + comp_unit_header->length;
    comp_unit = (void *)comp_unit_header + sizeof(struct dwarf_compilation_unit_header);

    index = dwarf_get_index(&comp_unit);
    abbrev = elf_ctx->abbrev_array[index];
    if (DW_TAG_compile_unit != abbrev->tag) {
        fprintf(stderr, "[E] first tag in info must be a compile unit!!!\n");
        return NULL;
    }
    tag_attrib = abbrev->tag_attrib;
    while (NULL != tag_attrib) {
        dwarf_form_parse(elf_ctx, tag_attrib, &comp_unit);
        tag_attrib = tag_attrib->next;
    }

    type_addr = dwarf_info_get_variable_type_in_tag_list(elf_ctx, &comp_unit, function_name, variable_name);
    //if (NULL != type_addr) {
    //    fprintf(stderr, "FOUND @ %p\n", type_addr);
    //    //hexdump(type_addr, 64);
    //}

    return type_addr;
}

static struct type_head *dwarf_get_type_from_form_list(struct elf_ctx *, void **, struct type_head *, size_t);

static struct type *
dwarf_get_type_from_form(struct elf_ctx *elf_ctx, void **addr, struct type_head *head, size_t level)
{
    uint8_t index;
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;
    struct form_data *data;
    struct type *this;
    void *ptr;

    index = dwarf_get_index(addr);
    //fprintf(stderr, "INDEX: %d (%ld)\n", (int)index, level);
    if (0 == index) {
        return NULL;
    }

    this = type_cache_get(*addr);
    if (NULL != this) {
        //fprintf(stderr, "FOUND IN CACHE!\n");
        return this;
    }

    this = type_new(*addr);
    if (NULL == this)
        return NULL;

    // DW_TAG_type_unit
    abbrev = elf_ctx->abbrev_array[index];
    this->tag = abbrev->tag;

    tag_attrib = abbrev->tag_attrib;
    while (NULL != tag_attrib) {
        data = dwarf_form_parse(elf_ctx, tag_attrib, addr);
        switch (tag_attrib->attrib) {
        case DW_AT_name:
            this->name = data->data.addr;
            //fprintf(stderr, "NAME: (%s)\n", this->name);
            break;
        case DW_AT_data_member_location:
            this->offset = data->data.integer;
            //fprintf(stderr, "LOC: (%s) %s %p\n", this->type?this->type->name:"", this->name, (void *)this->offset);
            break;
        case DW_AT_byte_size:
            this->byte_size = data->data.integer;
            //fprintf(stderr, "BS: (%s) %s %zd\n", this->type?this->type->name:"", this->name, this->byte_size);
            break;
        case DW_AT_upper_bound:
            this->upper_bound = data->data.integer;
            //fprintf(stderr, "UPPER BOUND: %s %s %zd\n", this->name, this->name, this->upper_bound);
            break;
        case DW_AT_encoding:
            this->encoding = data->data.integer;
            //fprintf(stderr, "ENC: %s %s %d\n", this->name, this->name, this->encoding);
            break;
        case DW_AT_type:
            ptr = data->data.addr;
            //fprintf(stderr, "ADDR TYPE = %p (%p)\n", ptr, data->base_addr);
            //hexdump_addr(ptr, 64, ptr - data->base_addr);
            this->type = dwarf_get_type_from_form(elf_ctx, &ptr, &this->child_head, level + 1);
            break;
        //case DW_AT_sibling:
        //case DW_AT_decl_file:
        //case DW_AT_decl_line:
        //    //fprintf(stderr, "ignoring tag\n");
        //    break;
        default:
            //fprintf(stderr, "unknown tag (0x%04x)\n", tag_attrib->attrib);
            break;
        }

        tag_attrib = tag_attrib->next;
    }

    if (DW_children_yes == abbrev->children) {
        dwarf_get_type_from_form_list(elf_ctx, addr, &this->child_head, level + 1);
        //that = dwarf_get_type_from_form(elf_ctx, type_unit, addr, head, level + 1);
        //if (NULL != that)
        //TAILQ_INSERT_TAIL(&this->siblings_head, that, next);
    }

    return this;
}

static struct type_head *
dwarf_get_type_from_form_list(struct elf_ctx *elf_ctx, void **addr, struct type_head *head, size_t level)
{
    struct type *ret_type;

    do {
        ret_type = dwarf_get_type_from_form(elf_ctx, addr, head, level);
        if (NULL != ret_type) {
            TAILQ_INSERT_TAIL(head, ret_type, next);
        }

    } while (NULL != ret_type);

    return head;
}

static void *
dwarf_find_type_addr_by_name_in_list(struct elf_ctx *elf_ctx, void **addr, char *type_name)
{
    uint8_t index;
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;
    //struct dwarf_compilation_unit_header *comp_unit_header;
    struct form_data *data;
    void *type_addr;

    type_addr = *addr;
    //comp_unit_header = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_info_sh->sh_offset;
    index = dwarf_get_index(addr);
    while (0 != index) {
        abbrev = elf_ctx->abbrev_array[index];

        tag_attrib = abbrev->tag_attrib;
        while (NULL != tag_attrib) {
            data = dwarf_form_parse(elf_ctx, tag_attrib, addr);
            if ((DW_TAG_base_type == abbrev->tag ||
                DW_TAG_array_type == abbrev->tag ||
                DW_TAG_typedef == abbrev->tag ||
                DW_TAG_structure_type == abbrev->tag) &&
                DW_AT_name == tag_attrib->attrib &&
                0 == strcmp(type_name, data->data.addr))
            {
                return type_addr;
            }

            tag_attrib = tag_attrib->next;
        }

        if (DW_children_yes == abbrev->children) {
            type_addr = dwarf_find_type_addr_by_name_in_list(elf_ctx, addr, type_name);
            if (NULL != type_addr) {
                return type_addr;
            }
        }

        type_addr = *addr;
        index = dwarf_get_index(addr);
    }

    return NULL;
}

static void *
dwarf_find_type_addr_by_name(struct elf_ctx *elf_ctx, char *type_name)
{
    struct dwarf_types_unit_header *type_unit_header;
    struct dwarf_compilation_unit_header *comp_unit_header;
    void *comp_unit;
    void *type_unit;
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;
    uint8_t index;
    void *type_addr;

    /*
     * COMPILATION UNIT
     */
    comp_unit_header = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_info_sh->sh_offset;
    comp_unit = (void *)comp_unit_header + sizeof(struct dwarf_compilation_unit_header);

    index = dwarf_get_index(&comp_unit);
    abbrev = elf_ctx->abbrev_array[index];
    if (DW_TAG_compile_unit != abbrev->tag) {
        fprintf(stderr, "[E] first tag in info must be a compile unit!!!\n");
        return NULL;
    }
    // step over compile unit
    tag_attrib = abbrev->tag_attrib;
    while (NULL != tag_attrib) {
        dwarf_form_parse(elf_ctx, tag_attrib, &comp_unit);
        tag_attrib = tag_attrib->next;
    }
    // find in .debug_info?
    type_addr = dwarf_find_type_addr_by_name_in_list(elf_ctx, &comp_unit, type_name);
    if (NULL != type_addr)
        return type_addr;

    /*
     * TYPE UNITS
     */
    type_unit_header = NULL;
    while (NULL != (type_unit_header = dwarf_types_type_unit_get_next(elf_ctx, type_unit_header))) {
        type_unit = (void *)type_unit_header + type_unit_header->offset;
        // find in .debug_types?
        type_addr = dwarf_find_type_addr_by_name_in_list(elf_ctx, &type_unit, type_name);
        if (NULL != type_addr)
            return type_addr;
    }

    return NULL;
}

static void *
dwarf_get_type_by_name(struct elf_ctx *elf_ctx, char *type_name)
{
    void *type_addr;
    struct type *type;

    type_addr = dwarf_find_type_addr_by_name(elf_ctx, type_name);
    if (NULL == type_addr)
        return NULL;

    type = dwarf_get_type_from_form(elf_ctx, &type_addr, NULL, 0);
    if (NULL == type)
        return NULL;

    return type;
}

static int
elf_section_header_parse(struct elf_ctx *elf_ctx)
{
    uint64_t section_header_offset;
    uint64_t section_header_entries;
    //uint64_t section_header_size;
    struct elf_section_header *elf_sh;
    struct elf_section_header *section_header;
    struct elf_section_header *section_names_header;
    size_t section_entry;
    char *section_names;

    section_header_offset = elf_ctx->elf_fh->e_shoff;
    //section_header_size = elf_ctx->elf_fh->e_ehsize;
    section_header_entries = elf_ctx->elf_fh->e_shnum;

    elf_sh = elf_ctx->elf_start_address + section_header_offset;

    // read section names
    if (SHN_UNDEF == elf_ctx->elf_fh->e_shstrndx)
        return -1;
    section_names_header = elf_sh + elf_ctx->elf_fh->e_shstrndx;
    //debug_print(section_names_header, "elf_section_header");
    section_names = elf_ctx->elf_start_address + section_names_header->sh_offset;
    if (NULL == section_names)
        return -1;

    // loop section headers
    section_entry = 0;
    while (section_entry < section_header_entries) {
        section_header = elf_sh + section_entry;
        if (0 == strcmp(".debug_info", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size);
            elf_ctx->dwarf_debug_info_sh = section_header;
        }
        if (0 == strcmp(".debug_line", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
        }
        if (0 == strcmp(".debug_str", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
            elf_ctx->dwarf_debug_str = elf_ctx->elf_start_address + section_header->sh_offset;
        }
        if (0 == strcmp(".debug_pubnames", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
        }
        if (0 == strcmp(".debug_pubtypes", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size);
        }
        if (0 == strcmp(".debug_types", section_names + section_header->sh_name)) {
            //debug_print_gdb(section_header, "elf_section_header");
            //elf_ctx->dwarf_debug_types = elf_ctx->elf_start_address + section_header->sh_offset;
            elf_ctx->dwarf_debug_types_sh = section_header;
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
        }
        if (0 == strcmp(".debug_aranges", section_names + section_header->sh_name)) {
            //hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
        }
        //if (0 == strcmp(".strtab", section_names + section_header->sh_name)) {
        //    hexdump(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size, 16);
        //}
        if (0 == strcmp(".debug_abbrev", section_names + section_header->sh_name)) {
            elf_ctx->dwarf_debug_abbrev_sh = section_header;
        }
        section_entry++;
    }

    //dwarf_abbrev_parse(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size);
    //dwarf_info_parse(elf_ctx->elf_start_address + section_header->sh_offset, section_header->sh_size);
    if (NULL == elf_ctx->dwarf_debug_str ||
        NULL == elf_ctx->dwarf_debug_abbrev_sh ||
        NULL == elf_ctx->dwarf_debug_info_sh)
    {
        fprintf(stderr, "[E] Not compiled with debug symbols!\n");
        exit(EXIT_FAILURE);
    }

    //dwarf_types_parse(elf_ctx->dwarf_debug_types);

    return 0;
}

static struct elf_ctx *
elf_open(void)
{
    extern const char *__progname;
    char magic[] = { '\177', 'E', 'L', 'F' };
    struct elf_ctx *elf_ctx;
    int ret;
    struct elf_ident *elf_ident;
    struct stat stat;

    elf_ctx = malloc(sizeof(struct elf_ctx));
    if (NULL == elf_ctx)
        goto err_malloc;

    elf_ctx->dwarf_debug_str = NULL;
    elf_ctx->dwarf_debug_info_sh = NULL;
    elf_ctx->dwarf_debug_abbrev_sh = NULL;
    elf_ctx->dwarf_debug_types_sh = NULL;

    // exe size
    ret = lstat(__progname, &stat);
    if (-1 == ret)
        goto err_stat;
    elf_ctx->elf_size = stat.st_size;

    // open
    //elfile = fopen("/proc/self/exe", "r");
    elf_ctx->elf_fd = open(__progname, O_RDONLY);
    if (-1 == elf_ctx->elf_fd) {
        perror("open");
        goto err_open;
    }

    // mmap
    elf_ctx->elf_start_address = mmap(NULL, elf_ctx->elf_size, PROT_READ, MAP_SHARED, elf_ctx->elf_fd, 0);
    if (MAP_FAILED == elf_ctx->elf_start_address) {
        perror("mmap");
        goto err_mmap;
    }
    elf_ctx->elf_fh = elf_ctx->elf_start_address;

    // magic?
    //debug_print(elf_ctx->elf_fh, "elf_file_header");
    elf_ident = (struct elf_ident *)elf_ctx->elf_fh;
    if (0 != memcmp(magic, &elf_ident->magic.magics, sizeof(magic))) {
        fprintf(stderr, "[E] ELF Magic error\n");
        goto err_elf_magic;
    }

    //debug_print(elf_ident, "elf_ident");
    return elf_ctx;

err_elf_magic:
    munmap(elf_ctx->elf_start_address, elf_ctx->elf_size);
err_mmap:
    close(elf_ctx->elf_fd);
err_open:
err_stat:
    free(elf_ctx);
err_malloc:
    return NULL;
}

static void
elf_close(struct elf_ctx *elf_ctx)
{
    munmap(elf_ctx->elf_start_address, elf_ctx->elf_size);
    free(elf_ctx);                                                                                              // free
}

#if 0
static int
testing_foo_function(void)
{
    struct new_struct_to_test {
        int cykel;
        float diskmaskin;
    };

    struct new_struct_to_test new = { 4, 5.6 };

    printf("%d %f", new.cykel, new.diskmaskin);
    return 0;
}
#endif
// #########################################################

static void
print_level_indent(size_t level)
{
    fputc('\n', stderr);
     while (level-- > 0)
         fputs("  ", stderr);
}

static void
print_type_name(struct type *type)
{
    struct type *that;

    if (NULL == type)
        return;

    print_type_name(type->type);

    switch (type->tag) {
    case DW_TAG_base_type:
        switch (type->encoding) {
        case DW_ATE_signed:
        case DW_ATE_signed_char:
            fprintf(stderr, "i%zd", type->byte_size);
            break;
        case DW_ATE_unsigned:
        case DW_ATE_unsigned_char:
            fprintf(stderr, "u%zd", type->byte_size);
            break;
        case DW_ATE_float:
            fprintf(stderr, "f%zd", type->byte_size);
            break;
        default:
            fprintf(stderr, "[0x%x]%zd", type->tag, type->byte_size);
            break;
        }
        break;
    case DW_TAG_pointer_type:
        // if next type is NULL -> void
        if (NULL == type->type)
            fputs("void ", stderr);
        else
            fputs(" ", stderr);

        fputs("*", stderr);
        break;
    case DW_TAG_array_type:
        TAILQ_FOREACH(that, &type->child_head, next) {
            // subrange
            if (DW_TAG_subrange_type != that->tag) {
                fprintf(stderr, "[E] must be subrange type!\n");
                exit(EXIT_FAILURE);
            }
            fprintf(stderr, "[%zd]", that->upper_bound + 1);
        }
        break;
    case DW_TAG_typedef:
        break;
    case DW_TAG_structure_type:
        fputs(type->name, stderr);
        break;
    default:
        fprintf(stderr, "[E] couldnt print base type name(%x,%zx)\n", type->encoding, type->byte_size);
        break;
    }
}

static void
print_as_base_type(struct type *type, void *data_addr)
{
    switch (type->encoding) {
    case DW_ATE_signed_char:
        switch (type->byte_size) {
        case 1:     fprintf(stderr, "%d", *(int8_t *)data_addr); break;
        }
        break;
    case DW_ATE_unsigned_char:
        switch (type->byte_size) {
        case 1:     fprintf(stderr, "%u", *(uint8_t *)data_addr); break;
        }
        break;
    case DW_ATE_signed:
        switch (type->byte_size) {
        case 1:     fprintf(stderr, "%d", *(int8_t *)data_addr); break;
        case 2:     fprintf(stderr, "%d", *(int16_t *)data_addr); break;
        case 4:     fprintf(stderr, "%d", *(int32_t *)data_addr); break;
        case 8:     fprintf(stderr, "%ld", *(int64_t *)data_addr); break;
        }
        break;
    case DW_ATE_unsigned:
        switch (type->byte_size) {
        case 1:     fprintf(stderr, "%u", *(uint8_t *)data_addr); break;
        case 2:     fprintf(stderr, "%u", *(uint16_t *)data_addr); break;
        case 4:     fprintf(stderr, "%u", *(uint32_t *)data_addr); break;
        case 8:     fprintf(stderr, "%lu", *(uint64_t *)data_addr); break;
        }
        break;
    case DW_ATE_float:
        fprintf(stderr, "%f", *(float *)data_addr);
        break;
    default:
        fprintf(stderr, "[E] Couldnt print base type (%x,%zu)\n", type->encoding, type->byte_size);
        break;
    }
}

static void print_as_type(struct type *type, void *addr, size_t level);    // prototype

static void
print_as_subrange(struct type *type, void **addr, size_t level, struct type *subrange)
{
    size_t i;
    size_t upper_bound;
    struct type *subrange_next;

    if (NULL == type || NULL == addr || NULL == subrange)
        return;

    if (DW_TAG_subrange_type != subrange->tag) {
        fprintf(stderr, "[E] Must be subrange tag!\n");
        exit(EXIT_FAILURE);
    }

    upper_bound = subrange->upper_bound + 1;
    subrange_next = TAILQ_NEXT(subrange, next);

    fputs("{ ", stderr);
    //print_level_indent(level);
    for (i = 0; i < upper_bound; i++) {
        if (NULL == subrange_next) {
            if (DW_TAG_base_type == type->tag) {
                print_as_type(type, *addr, level + 1);
                *addr += type->byte_size;   // kind of a hack, but works...
                if (i + 1 < upper_bound)
                    fputs(", ", stderr);
            } else {
                print_level_indent(level + 1);
                fprintf(stderr, "[%zu] = ", i);
                print_as_type(type, *addr, level + 1);
                *addr += type->byte_size;   // kind of a hack, but works...
            }
        } else {
            print_as_subrange(type, addr, level + 7, subrange_next);
            if (i + 1 < upper_bound)
                fputs(", ", stderr);
        }
    }

    if (DW_TAG_base_type == type->tag) {
        fputs(" }", stderr);
    } else {
        print_level_indent(level);
        fputs("}", stderr);
    }

}

static void
print_as_array(struct type *type, void *addr, size_t level)
{
    struct type *this;

    this = type->type;
    if (NULL == this) {
        fprintf(stderr, "[E] array must have a type!\n");
        exit(EXIT_FAILURE);
    }

    print_as_subrange(this, &addr, level, TAILQ_FIRST(&type->child_head));

}

static void
print_as_struct(struct type *type, void *addr, size_t level)
{
    struct type *this;

    if (NULL != type->type) {
        fprintf(stderr, "[E] structure cant refer to a subtype!\n");
        exit(EXIT_FAILURE);
    }

    //print_level_indent(level);
    fprintf(stderr, "{");
    TAILQ_FOREACH(this, &type->child_head, next) {
        // members
        if (DW_TAG_member != this->tag) {
            fprintf(stderr, "[E] must be member tag!\n");
            exit(EXIT_FAILURE);
        }

        //fprintf(stderr, "MEMBER %s = ", this->name);
        print_level_indent(level + 1);
        fprintf(stderr, "%s", this->name);
        fprintf(stderr, " (");
        print_type_name(this->type);
        fprintf(stderr, ") = ");
        print_as_type(this, addr + this->offset, level + 1);
        fputs("", stderr);
    }
    print_level_indent(level);
    fputs("}", stderr);
}

static void
print_as_type(struct type *type, void *addr, size_t level)
{
    void *data_addr;
    struct type *this;

    data_addr = addr + type->offset;

    switch (type->tag) {
    case DW_TAG_base_type:
        print_as_base_type(type, data_addr);
        break;
    case DW_TAG_pointer_type:
        if (NULL == *(void **)data_addr)
            fputs("NULL", stderr);
        else
            fprintf(stderr, "%p", *(void **)data_addr);
        break;
    case DW_TAG_array_type:
        print_as_array(type, addr, level);
        break;
    case DW_TAG_typedef:
        if (NULL != type->type)
            print_as_type(type->type, addr, level);
        else
            fprintf(stderr, "[E] typedef has no subtype!");
        break;
    case DW_TAG_structure_type:
        print_as_struct(type, addr, level);
        break;
    case DW_TAG_member:
        this = type->type;
        if (NULL == this) {
             fprintf(stderr, "[E] member must have a type!");
             return;
        }
        print_as_type(this, addr, level);
        break;
    default:
        fprintf(stderr, "[E] ?????");
        break;
    }
}

#if 0
static struct type *
dwarf_find_type_of_variable(struct elf_ctx *elf_ctx, const char *variable_name)
{
    struct dwarf_types_unit_header *type_unit_header;
    void *tag_addr;
    struct type *ret_type;

    tag_addr = NULL;
    type_unit_header = NULL;
    while (NULL != (type_unit_header = dwarf_types_type_unit_get_next(elf_ctx, type_unit_header))) {
        tag_addr = dwarf_types_get_tag(elf_ctx, type_unit_header, struct_name);
        if (NULL != tag_addr)
            break;
    }

    if (NULL == type_unit_header || NULL == tag_addr) {
        fprintf(stderr, "NO SUCH TYPE!!! (%s)\n", struct_name);
        return;
    }

}
#endif

static void
dwarf_open(struct elf_ctx *elf_ctx) {
    elf_section_header_parse(elf_ctx);

    dwarf_abbrev_parse(elf_ctx);
}

static void
dwarf_close(struct elf_ctx *elf_ctx)
{
    struct abbrev *abbrev, *abbrev_next;
    struct tag_attrib *tag_attrib, *tag_attrib_next;
    uint8_t index;

    // clean up abbrev
    index = 1;      // 0 index is never used
    abbrev = elf_ctx->abbrev_array[index];
    while (NULL != abbrev) {
        tag_attrib = abbrev->tag_attrib;
        while (NULL != tag_attrib) {
            tag_attrib_next = tag_attrib->next;
            free(tag_attrib);                                                                                   // free
            tag_attrib = tag_attrib_next;
        }

        index++;
        abbrev_next = elf_ctx->abbrev_array[index];
        free(abbrev);                                                                                           // free
        abbrev = abbrev_next;
    }

    free(elf_ctx->abbrev_array);                                                                                // free
    elf_ctx->abbrev_array = NULL;
}

static struct elf_ctx *
print_open(void)
{
    struct elf_ctx *elf_ctx;

    elf_ctx = elf_open();
    dwarf_open(elf_ctx);

    TAILQ_INIT(&type_cache_head);

    return elf_ctx;
}

static void
print_close(struct elf_ctx *elf_ctx, struct type *type)
{
    // clean up type
    type_remove_all();

    dwarf_close(elf_ctx);
    elf_close(elf_ctx);
}

static void
print_struct_real(struct elf_ctx *elf_ctx, void *addr, struct type *type)
{
    fputs("(", stderr);
    print_type_name(type);
    fprintf(stderr, ") %p = ", addr);
    print_as_type(type, addr, 0);
    fputc('\n', stderr);
}

void
print_variable(void *addr, char *function_name, char *variable_name)
{
    void *type_addr;
    struct elf_ctx *elf_ctx;
    struct type *type;

    elf_ctx = print_open();

    type_addr = dwarf_info_get_variable_type(elf_ctx, function_name, variable_name);
    if (NULL == type_addr) {
        fprintf(stderr, "[E] didnt find variable or type\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_INIT(&type_cache_head);
    //TAILQ_INIT(&type_head);
    //ret_type = dwarf_get_type_from_form(elf_ctx, &type_info_addr, &type_head, 0);
    type = dwarf_get_type_from_form(elf_ctx, &type_addr, NULL, 0);
    if (NULL == type) {
        fprintf(stderr, "[E] Failed to get type from form\n");
        return;
    }

    print_struct_real(elf_ctx, addr, type);
    print_close(elf_ctx, type);

    return;
}

void
print_type(void *addr, char *type_name)
{
    struct elf_ctx *elf_ctx;
    struct type *type;

    elf_ctx = print_open();

    type = dwarf_get_type_by_name(elf_ctx, type_name);
    if (NULL == type) {
        fprintf(stderr, "[E] didnt find type!\n");
        return;
    }

    print_struct_real(elf_ctx, addr, type);
    print_close(elf_ctx, type);

    return;
}

#ifdef TEST_INKDWARF
#include <netinet/ip.h>

// #########################################################
struct monkey {
    int lemon;
    char citrus;
};

struct struct_to_debug {
    int apa;
    float banan;
    int cyclops[13];
    char dummy[3][4];
    struct monkey ebola[3];
    void *test;
    //void *next;
    struct struct_to_debug *next;
};
// #########################################################

int
main(void)
{
    struct sockaddr_in sin;

    struct struct_to_debug struct_to_debug_instance = { 1, 2.3, { 5, 6, 7, 8, 9, 10, 11},
        { { 99, 88, 77, 66}, { 33, 22, 11 } }, { { 12, 13 } }, NULL, &struct_to_debug_instance};

    signal(SIGSEGV, debug_backtrace);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 999;
    sin.sin_addr.s_addr = 7777777;

    print_variable(&struct_to_debug_instance, "main", "struct_to_debug_instance");

    print_type(&struct_to_debug_instance, "struct_to_debug");
    print_type(&sin, "sockaddr_in");

    return 0;
}
#endif // TEST_INKDWARF

#endif // NDEBUG
#endif // __INKDWARF__
