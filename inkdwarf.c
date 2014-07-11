#define _BSD_SOURCE
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


#include <bsd/sys/queue.h>

#include "inkdwarf.h"

void
hexdump(void *ptr, size_t len)
{
    unsigned char *buffer = ptr, c;
    size_t idx = 0;
    char ascii[16 + 1] = { 0 };
    while (1) {
        if (0 == idx % 16) printf("%08lx ", idx);
        if (idx < len) {
            printf("%02x ", c = buffer[idx]);
            ascii[idx%16] = isgraph(c) ? c : '.';
        } else {
            printf("   ");
            ascii[idx%16] = '\0';
        }
        if (0 == ++idx % 8)
            putchar(' ');
        if (0 == idx % 16) {
            printf("%s\n", ascii);
            if (idx >= len) break;
        }
    }
}

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

/*
 *static int
 *dwarf_info_entry_parse(void *ptr, uint8_t index)
 *{
 *    //if (index != ptr[0]) {
 *    //    fprintf(stderr, "ERROR: " ## __FUNCTION__ ## ": Index missmatch!\n");
 *    //    return -1;
 *    //}
 *
 *    ptr++;
 *
 *    return 0;
 *}
 */

#if 0
static int
dwarf_info_parse(void *ptr, size_t len)
{
    struct dwarf_compilation_unit_header *comp_unit_header;
    //struct dwarf_compilation_unit *comp_unit;
    size_t temp_len;

    if (NULL == ptr)
        return -1;

    //hexdump(ptr, si<aqzeof(struct dwarf_compilation_unit_header), 16);
    comp_unit_header = ptr;
    //debug_print_gdb(comp_unit_header, "dwarf_compilation_unit_header");
    temp_len = sizeof(struct dwarf_compilation_unit_header);
    ptr += temp_len;
    len -= temp_len;

    /*
     *hexdump(ptr, sizeof(struct dwarf_compilation_unit), 16);
     *comp_unit = ptr;
     *debug_print_gdb(comp_unit, "dwarf_compilation_unit");
     *temp_len = sizeof(struct dwarf_compilation_unit);
     *ptr += temp_len;
     *len -= temp_len;
     *hexdump(ptr, len, 16);
     */

     /*
      * ENTRIES
      */

    // DW_TAG
    switch (*(char *)ptr) {
    case DW_TAG_ptr_to_member_type:
        fprintf(stderr, "PTR TO MEMB TYPE\n");
        break;
    case DW_TAG_compile_unit:
        fprintf(stderr, "COMP UNIT\n");
        break;
    default:
        fprintf(stderr, "TAG: %d\n", (int)*(char *)ptr);
        break;
    }
    return 0;
}
#endif

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


/* */
struct type_and_name {
    char *type_name;
    char *var_name;
    size_t byte_size;
    // int encoding;    // always assume same as machine!
    struct type_and_name *sibling;
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
/* */

/*
        switch (tag) {
        case DW_TAG_array_type:
            printf("DW_TAG_array_type\n");
            break;
        case DW_TAG_class_type:
            printf("DW_TAG_class_type\n");
            break;
        case DW_TAG_entry_point:
            printf("DW_TAG_entry_point\n");
            break;
        case DW_TAG_enumeration_type:
            printf("DW_TAG_enumeration_type\n");
            break;
        case DW_TAG_formal_parameter:
            printf("DW_TAG_formal_parameter\n");
            break;
        case DW_TAG_imported_declaration:
            printf("DW_TAG_imported_declaration\n");
            break;
        case DW_TAG_label:
            printf("DW_TAG_label\n");
            break;
        case DW_TAG_lexical_block:
            printf("DW_TAG_lexical_block\n");
            break;
        case DW_TAG_member:
            printf("DW_TAG_member\n");
            break;
        case DW_TAG_pointer_type:
            printf("DW_TAG_pointer_type\n");
            break;
        case DW_TAG_reference_type:
            printf("DW_TAG_reference_type\n");
            break;
        case DW_TAG_compile_unit:
            printf("DW_TAG_compile_unit\n");
            break;
        case DW_TAG_string_type:
            printf("DW_TAG_string_type\n");
            break;
        case DW_TAG_structure_type:
            printf("DW_TAG_structure_type\n");
            break;
        case DW_TAG_subroutine_type:
            printf("DW_TAG_subroutine_type\n");
            break;
        case DW_TAG_typedef:
            printf("DW_TAG_typedef\n");
            break;
        case DW_TAG_union_type:
            printf("DW_TAG_union_type\n");
            break;
        case DW_TAG_unspecified_parameters:
            printf("DW_TAG_unspecified_parameters\n");
            break;
        case DW_TAG_variant:
            printf("DW_TAG_variant\n");
            break;
        case DW_TAG_common_block:
            printf("DW_TAG_common_block\n");
            break;
        case DW_TAG_common_inclusion:
            printf("DW_TAG_common_inclusion\n");
            break;
        case DW_TAG_inheritance:
            printf("DW_TAG_inheritance\n");
            break;
        case DW_TAG_inlined_subroutine:
            printf("DW_TAG_inlined_subroutine\n");
            break;
        case DW_TAG_module:
            printf("DW_TAG_module\n");
            break;
        case DW_TAG_ptr_to_member_type:
            printf("DW_TAG_ptr_to_member_type\n");
            break;
        case DW_TAG_set_type:
            printf("DW_TAG_set_type\n");
            break;
        case DW_TAG_subrange_type:
            printf("DW_TAG_subrange_type\n");
            break;
        case DW_TAG_with_stmt:
            printf("DW_TAG_with_stmt\n");
            break;
        case DW_TAG_access_declaration:
            printf("DW_TAG_access_declaration\n");
            break;
        case DW_TAG_base_type:
            printf("DW_TAG_base_type\n");
            break;
        case DW_TAG_catch_block:
            printf("DW_TAG_catch_block\n");
            break;
        case DW_TAG_const_type:
            printf("DW_TAG_const_type\n");
            break;
        case DW_TAG_constant:
            printf("DW_TAG_constant\n");
            break;
        case DW_TAG_enumerator:
            printf("DW_TAG_enumerator\n");
            break;
        case DW_TAG_file_type:
            printf("DW_TAG_file_type\n");
            break;
        case DW_TAG_friend:
            printf("DW_TAG_friend\n");
            break;
        case DW_TAG_namelist:
            printf("DW_TAG_namelist\n");
            break;
        case DW_TAG_namelist_item:
            printf("DW_TAG_namelist_item\n");
            break;
        case DW_TAG_packed_type:
            printf("DW_TAG_packed_type\n");
            break;
        case DW_TAG_subprogram:
            printf("DW_TAG_subprogram\n");
            break;
        case DW_TAG_template_type_parameter:
            printf("DW_TAG_template_type_parameter\n");
            break;
        case DW_TAG_template_value_parameter:
            printf("DW_TAG_template_value_parameter\n");
            break;
        case DW_TAG_thrown_type:
            printf("DW_TAG_thrown_type\n");
            break;
        case DW_TAG_try_block:
            printf("DW_TAG_try_block\n");
            break;
        case DW_TAG_variant_part:
            printf("DW_TAG_variant_part\n");
            break;
        case DW_TAG_variable:
            printf("DW_TAG_variable\n");
            break;
        case DW_TAG_volatile_type:
            printf("DW_TAG_volatile_type\n");
            break;
        case DW_TAG_dwarf_procedure:
            printf("DW_TAG_dwarf_procedure\n");
            break;
        case DW_TAG_restrict_type:
            printf("DW_TAG_restrict_type\n");
            break;
        case DW_TAG_interface_type:
            printf("DW_TAG_interface_type\n");
            break;
        case DW_TAG_namespace:
            printf("DW_TAG_namespace\n");
            break;
        case DW_TAG_imported_module:
            printf("DW_TAG_imported_module\n");
            break;
        case DW_TAG_unspecified_type:
            printf("DW_TAG_unspecified_type\n");
            break;
        case DW_TAG_partial_unit:
            printf("DW_TAG_partial_unit\n");
            break;
        case DW_TAG_imported_unit:
            printf("DW_TAG_imported_unit\n");
            break;
        case DW_TAG_mutable_type:
            printf("DW_TAG_mutable_type\n");
            break;
        case DW_TAG_condition:
            printf("DW_TAG_condition\n");
            break;
        case DW_TAG_shared_type:
            printf("DW_TAG_shared_type\n");
            break;
        case DW_TAG_type_unit:
            printf("DW_TAG_type_unit\n");
            break;
        case DW_TAG_rvalue_reference_type:
            printf("DW_TAG_rvalue_reference_type\n");
            break;
        case DW_TAG_template_alias:
            printf("DW_TAG_template_alias\n");
            break;
        case DW_TAG_lo_user:
            printf("DW_TAG_lo_user\n");
            break;
        case DW_TAG_MIPS_loop:
            printf("DW_TAG_MIPS_loop\n");
            break;
        case DW_TAG_HP_array_descriptor:
            printf("DW_TAG_HP_array_descriptor\n");
            break;
        case DW_TAG_format_label:
            printf("DW_TAG_format_label\n");
            break;
        case DW_TAG_function_template:
            printf("DW_TAG_function_template\n");
            break;
        case DW_TAG_class_template:
            printf("DW_TAG_class_template\n");
            break;
        case DW_TAG_GNU_BINCL:
            printf("DW_TAG_GNU_BINCL\n");
            break;
        case DW_TAG_GNU_EINCL:
            printf("DW_TAG_GNU_EINCL\n");
            break;
        case DW_TAG_GNU_template_template_parameter:
            printf("DW_TAG_GNU_template_template_parameter\n");
            break;
        //case DW_TAG_GNU_template_template_param:
        //    printf("DW_TAG_GNU_template_template_param\n");
        //    break;
        case DW_TAG_GNU_template_parameter_pack:
            printf("DW_TAG_GNU_template_parameter_pack\n");
            break;
        case DW_TAG_GNU_formal_parameter_pack:
            printf("DW_TAG_GNU_formal_parameter_pack\n");
            break;
        case DW_TAG_GNU_call_site:
            printf("DW_TAG_GNU_call_site\n");
            break;
        case DW_TAG_GNU_call_site_parameter:
            printf("DW_TAG_GNU_call_site_parameter\n");
            break;
        case DW_TAG_ALTIUM_circ_type:
            printf("DW_TAG_ALTIUM_circ_type\n");
            break;
        case DW_TAG_ALTIUM_mwa_circ_type:
            printf("DW_TAG_ALTIUM_mwa_circ_type\n");
            break;
        case DW_TAG_ALTIUM_rev_carry_type:
            printf("DW_TAG_ALTIUM_rev_carry_type\n");
            break;
        case DW_TAG_ALTIUM_rom:
            printf("DW_TAG_ALTIUM_rom\n");
            break;
        case DW_TAG_upc_shared_type:
            printf("DW_TAG_upc_shared_type\n");
            break;
        case DW_TAG_upc_strict_type:
            printf("DW_TAG_upc_strict_type\n");
            break;
        case DW_TAG_upc_relaxed_type:
            printf("DW_TAG_upc_relaxed_type\n");
            break;
        case DW_TAG_PGI_kanji_type:
            printf("DW_TAG_PGI_kanji_type\n");
            break;
        case DW_TAG_PGI_interface_block:
            printf("DW_TAG_PGI_interface_block\n");
            break;
        case DW_TAG_SUN_function_template:
            printf("DW_TAG_SUN_function_template\n");
            break;
        case DW_TAG_SUN_class_template:
            printf("DW_TAG_SUN_class_template\n");
            break;
        case DW_TAG_SUN_struct_template:
            printf("DW_TAG_SUN_struct_template\n");
            break;
        case DW_TAG_SUN_union_template:
            printf("DW_TAG_SUN_union_template\n");
            break;
        case DW_TAG_SUN_indirect_inheritance:
            printf("DW_TAG_SUN_indirect_inheritance\n");
            break;
        case DW_TAG_SUN_codeflags:
            printf("DW_TAG_SUN_codeflags\n");
            break;
        case DW_TAG_SUN_memop_info:
            printf("DW_TAG_SUN_memop_info\n");
            break;
        case DW_TAG_SUN_omp_child_func:
            printf("DW_TAG_SUN_omp_child_func\n");
            break;
        case DW_TAG_SUN_rtti_descriptor:
            printf("DW_TAG_SUN_rtti_descriptor\n");
            break;
        case DW_TAG_SUN_dtor_info:
            printf("DW_TAG_SUN_dtor_info\n");
            break;
        case DW_TAG_SUN_dtor:
            printf("DW_TAG_SUN_dtor\n");
            break;
        case DW_TAG_SUN_f90_interface:
            printf("DW_TAG_SUN_f90_interface\n");
            break;
        case DW_TAG_SUN_fortran_vax_structure:
            printf("DW_TAG_SUN_fortran_vax_structure\n");
            break;
        case DW_TAG_SUN_hi:
            printf("DW_TAG_SUN_hi\n");
            break;
        case DW_TAG_hi_user:
            printf("DW_TAG_hi_user\n");
            break;
        default:
            break;
        }

*/

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
    elf_ctx->abbrev_array = calloc(128 * sizeof(void *), 1);
    if (NULL == elf_ctx->abbrev_array)
        return -1;

    abbrev_array_len = 128;

    index = 1;
    while (1) {
        //hexdump(ptr, len, 16);

        fprintf(stderr, "INDEX %d\n", index);
        if (index != ptr[0]) {
            // 0 == end of segments
            if (0 == ptr[0])
                return 0;

            fprintf(stderr, "index missmatch (%x != %x\n", index, ptr[0]);
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
                free(elf_ctx->abbrev_array);
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

#if 0
static int
dwarf_types_parse2(struct elf_ctx *elf_ctx, uint16_t index, void *ptr)
{
    struct abbrev *abbrev;
    struct tag_attrib *tag_attrib;

    abbrev = elf_ctx->abbrev_array[index];

    switch (form) {
    case DW_FORM_addr:
        len = sizeof(void *);
        break;
    case DW_FORM_block2:
    case DW_FORM_data2:
    case DW_FORM_ref2:
        len = 2;
        break;
    case DW_FORM_block4:
    case DW_FORM_data4:
    case DW_FORM_strp:
    case DW_FORM_ref4:
        len = 4;
        break;
    case DW_FORM_data8:
    case DW_FORM_ref8:
        len = 8;
        break;
    case DW_FORM_string:
        len = 0;
        break;
    case DW_FORM_block1:
    case DW_FORM_data1:
    case DW_FORM_ref1:
        len = 1;
        break;
    case DW_FORM_block:
    case DW_FORM_flag:
    case DW_FORM_sdata:
    case DW_FORM_udata:
    case DW_FORM_ref_addr:
    case DW_FORM_ref_udata:
    case DW_FORM_indirect:
    case DW_FORM_sec_offset:
    case DW_FORM_exprloc:
    case DW_FORM_flag_present:
    case DW_FORM_ref_sig8:
    default:
        len = 0;
        hexdump(*ptr, 8);
        break;
    }

    *ret_len = len;
    return form;
}


}
#endif

static int
dwarf_form_parse(struct elf_ctx *elf_ctx, struct tag_attrib *tag_attrib, void **ret_ptr)
{
    void *ptr = *ret_ptr;
    union {
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        void *addr;
    } data;
    //size_t byte_size = 0;

    memset(&data, 0, sizeof(data));

    switch (tag_attrib->form) {
    case DW_FORM_addr:
        printf("ADDR NOT IMPLEMENTED\n");
        break;
    case DW_FORM_block2:
        printf("BLOCK2 NOT IMPLEMENTED\n");
        break;
    case DW_FORM_block4:
        printf("BLOCK4 NOT IMPLEMENTED\n");
        break;
    case DW_FORM_data2:
        data.uint16 = *(uint16_t *)ptr;
        ptr += 2;
        break;
    case DW_FORM_data4:
        data.uint32 = *(uint32_t *)ptr;
        ptr += 4;
        break;
    case DW_FORM_data8:
        data.uint64 = *(uint64_t *)ptr;
        ptr += 8;
        break;
    case DW_FORM_string:
        data.addr = ptr;
        ptr += strlen(ptr) + 1;
        printf("STRING: \"%s\"\n", (char *)data.addr);
        break;
    case DW_FORM_block:
        printf("BLOCK NOT IMPLEMENTED\n");
        break;
    case DW_FORM_block1:
        printf("BLOCK1 NOT IMPLEMENTED\n");
        break;
    case DW_FORM_data1:
        data.uint8 = *(uint8_t *)ptr;
        ptr += 1;
        break;
    case DW_FORM_flag:
        printf("FLAG NOT IMPLEMENTED\n");
        break;
    case DW_FORM_sdata:
        data.uint64 = dwarf_parse_leb128((uint8_t **)&ptr);
        break;
    case DW_FORM_strp:
        data.addr = elf_ctx->dwarf_debug_str + *(uint32_t *)ptr;
        ptr += 4;
        printf("STRP: \"%s\"\n", (char *)data.addr);
        break;
    case DW_FORM_udata:
        printf("UDATA NOT IMPLEMENTED\n");
        break;
    case DW_FORM_ref_addr:
        printf("REF ADDR NOT IMPLEMENTED\n");
        break;
    case DW_FORM_ref1:
        data.uint8 = *(uint8_t *)ptr;
        ptr += 1;
        break;
    case DW_FORM_ref2:
        data.uint16 = *(uint16_t *)ptr;
        ptr += 2;
        break;
    case DW_FORM_ref4:
        data.uint32 = *(uint32_t *)ptr;
        ptr += 4;
        break;
    case DW_FORM_ref8:
        data.uint64 = *(uint64_t *)ptr;
        ptr += 8;
        break;
    case DW_FORM_ref_udata:
        printf("REF UDATA NOT IMPLEMENTED\n");
        break;
    case DW_FORM_indirect:
        printf("INDIRECT NOT IMPLEMENTED\n");
        break;
    case DW_FORM_sec_offset:
        data.uint32 = *(uint32_t *)ptr;
        ptr += 4;
        break;
    case DW_FORM_exprloc:
        printf("EXPRLOC NOT IMPLEMENTED\n");
        break;
    case DW_FORM_flag_present:
        printf("FLAG PRES NOT IMPLEMENTED\n");
        break;
    case DW_FORM_ref_sig8:
        data.uint64 = *(uint64_t *)ptr;
        ptr += 8;
        break;
    default:
        hexdump(ptr, 32);
        break;
    }

#if 0
    case DW_AT_sibling: // ??
        break;
    case DW_AT_name:
        break;
    case DW_AT_ordering:
        break;
    case DW_AT_byte_size:
        break;
    case DW_AT_bit_offset:
        break;
    case DW_AT_bit_size:
        break;
    case DW_AT_element_list:
        break;
    case DW_AT_language:
        language = 1;
        break;
    case DW_AT_member:
        break;
    case DW_AT_base_types:
        break;
    case DW_AT_type:
        break;
    default:
        printf("UNIMPLEMENTED AT!\n");
        hexdump(ptr, 10);
        break;
    }
#endif
    fprintf(stderr, "data: %lx\n", data.uint64);

    *ret_ptr = ptr;
    return 0;
}

static int
dwarf_types_find(struct elf_ctx *elf_ctx, char *struct_name)
{
    void *ptr = elf_ctx->elf_start_address + elf_ctx->dwarf_debug_types_sh->sh_offset;
    struct abbrev *abbrev;
    //struct dwarf_compilation_unit_header *comp_unit_header;
    struct dwarf_types_unit_header *types_header;
    uint8_t index;
    struct tag_attrib *tag_attrib;
    void *start_ptr;
    size_t len;
    int level;

    len = elf_ctx->dwarf_debug_types_sh->sh_size;
    start_ptr = ptr;
    while ((size_t)(ptr - start_ptr) < len) {
        // Types Unit Header
        types_header = ptr;
        ptr += sizeof(struct dwarf_types_unit_header);

        level = 1;
        while (0 < level) {
            // index
            index = *(uint8_t *)ptr++;
            if (0 == index) {
                level--;
                continue;
            }

            // DW_TAG_type_unit
            abbrev = elf_ctx->abbrev_array[index];
            switch (abbrev->tag) {
            case DW_TAG_structure_type:
            case DW_TAG_array_type:
            case DW_TAG_union_type:
            case DW_TAG_enumeration_type:
                level++;
                break;
            }
            //printf("TAG: %x (l=%d)\n", abbrev->tag, level);
            tag_attrib = abbrev->tag_attrib;
            while (NULL != tag_attrib) {
                if (DW_AT_signature == tag_attrib->attrib)
                    level--;    // TODO: is this correct???

                dwarf_form_parse(elf_ctx, tag_attrib, &ptr);
                if (DW_AT_name == tag_attrib->attrib)
                    printf("DW_AT_name = \"%s\"\n", tag_attrib->form;
                tag_attrib = tag_attrib->next;
            }
        }
    }

    return 0;
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
            debug_print_gdb(section_header, "elf_section_header");
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
        NULL == elf_ctx->dwarf_debug_info_sh ||
        NULL == elf_ctx->dwarf_debug_types_sh)
    {
        fprintf(stderr, "ERROR: Not compiled with debug symbols!\n");
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
        fprintf(stderr, "ELF Magic error\n");
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
    free(elf_ctx);
}

// #########################################################
struct struct_to_debug {
    int apa;
    float banan;
};

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
// #########################################################

#if 0
static size_t
abbrev_find_name_offset(void *abbrev_ptr)
{

}
#endif

#if 0
static struct type_and_name *
type_to_name(void *types_ptr, void *abbrev_ptr)
{

}
#endif

struct type_and_name *
elf_find_type(struct elf_ctx *elf_ctx, char *type_str)
{

}

int
main(void)
{
    struct elf_ctx *elf_ctx;
    struct struct_to_debug struct_to_debug_instance = { 1, 2.3 };

    elf_ctx = elf_open();
    printf("ELF Version: %d\n", elf_ctx->elf_fh->e_version);
    elf_section_header_parse(elf_ctx);
    dwarf_abbrev_parse(elf_ctx);
    dwarf_types_find(elf_ctx, "struct_to_debug");
    //elf_find_type(elf_ctx, "struct_to_debug");
    elf_close(elf_ctx);

    printf("ADDRESS: %p\n", &struct_to_debug_instance);

    return 0;
}
