// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_store_helper.h"
#include "export_program_info.h"
#include "store_helper_internal.h"
#include "windows_program_type.h"

#include <codecvt>

#include "ebpf_general_helpers.c"

#define REG_CREATE_FLAGS (KEY_WRITE | DELETE | KEY_READ)
#define REG_OPEN_FLAGS (DELETE | KEY_READ)

// // XDP_TEST helper function prototype descriptors.
// static const ebpf_helper_function_prototype_t _xdp_ebpf_extension_helper_function_prototype[] = {
//     {XDP_EXT_HELPER_FUNCTION_START + 1,
//      "bpf_xdp_adjust_head",
//      EBPF_RETURN_TYPE_INTEGER,
//      {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_ANYTHING}}};

// // XDP_TEST program information.
// static const ebpf_context_descriptor_t _ebpf_xdp_context_descriptor = {
//     sizeof(xdp_md_t),
//     EBPF_OFFSET_OF(xdp_md_t, data),
//     EBPF_OFFSET_OF(xdp_md_t, data_end),
//     EBPF_OFFSET_OF(xdp_md_t, data_meta)};

static const ebpf_program_info_t _mock_xdp_program_info = {
    {"xdp", &_ebpf_xdp_test_context_descriptor, EBPF_PROGRAM_TYPE_XDP_GUID, BPF_PROG_TYPE_XDP},
    EBPF_COUNT_OF(_xdp_test_ebpf_extension_helper_function_prototype),
    _xdp_test_ebpf_extension_helper_function_prototype};

typedef struct _ebpf_program_section_info_with_count
{
    _Field_size_(section_info_count) const ebpf_program_section_info_t* section_info;
    size_t section_info_count;
} ebpf_program_section_info_with_count_t;

static const ebpf_program_info_t* program_information_array[] = {
    &_ebpf_bind_program_info,
    &_ebpf_sock_addr_program_info,
    &_ebpf_sock_ops_program_info,
    &_ebpf_xdp_test_program_info,
    &_sample_ebpf_extension_program_info,
    &_mock_xdp_program_info};

ebpf_program_section_info_t _sample_ext_section_info[] = {
    {L"sample_ext", &EBPF_PROGRAM_TYPE_SAMPLE, &EBPF_ATTACH_TYPE_SAMPLE, BPF_PROG_TYPE_SAMPLE, BPF_ATTACH_TYPE_SAMPLE}};

ebpf_program_section_info_t _mock_xdp_section_info[] = {
    {L"xdp", &EBPF_PROGRAM_TYPE_XDP, &EBPF_ATTACH_TYPE_XDP, BPF_PROG_TYPE_XDP, BPF_XDP}};

static std::vector<ebpf_program_section_info_with_count_t> _section_information = {
    {&_ebpf_bind_section_info[0], _countof(_ebpf_bind_section_info)},
    {&_ebpf_xdp_test_section_info[0], _countof(_ebpf_xdp_test_section_info)},
    {&_ebpf_sock_addr_section_info[0], _countof(_ebpf_sock_addr_section_info)},
    {&_ebpf_sock_ops_section_info[0], _countof(_ebpf_sock_ops_section_info)},
    {&_sample_ext_section_info[0], _countof(_sample_ext_section_info)},
    {&_mock_xdp_section_info[0], _countof(_mock_xdp_section_info)},
};

uint32_t
export_all_program_information()
{
    uint32_t status = ERROR_SUCCESS;
    size_t array_size = _countof(program_information_array);
    for (uint32_t i = 0; i < array_size; i++) {
        status = ebpf_store_update_program_information(program_information_array[i], 1);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }

    return status;
}

uint32_t
export_all_section_information()
{
    uint32_t status = ERROR_SUCCESS;
    for (const auto& section : _section_information) {
        status = ebpf_store_update_section_information(section.section_info, (uint32_t)section.section_info_count);
        if (status != ERROR_SUCCESS) {
            break;
        }
    }

    return status;
}

int
export_global_helper_information()
{
    return ebpf_store_update_global_helper_information(
        ebpf_core_helper_function_prototype, ebpf_core_helper_functions_count);
}

uint32_t
clear_all_ebpf_stores()
{
    std::cout << "Clearing eBPF store" << std::endl;
    return ebpf_store_clear(ebpf_store_root_key);
}

void
print_help(_In_z_ const char* file_name)
{
    std::cerr << "Usage: " << file_name << " [--clear]" << std::endl;
}
