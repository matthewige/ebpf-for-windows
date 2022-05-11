// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "api_common.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "spec_type_descriptors.hpp"

struct bpf_object;

typedef struct _ebpf_ring_buffer_subscription ring_buffer_subscription_t;

typedef struct bpf_program
{
    struct bpf_object* object;
    char* section_name;
    char* program_name;
    uint8_t* byte_code;
    uint32_t byte_code_size;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;
    ebpf_handle_t handle;
    fd_t fd;
    bool pinned;
} ebpf_program_t;

typedef struct bpf_map
{
    const struct bpf_object* object;
    char* name;

    // Map handle generated by the execution context.
    ebpf_handle_t map_handle;

    // Map ID generated by the execution context.
    ebpf_id_t map_id;

    // File descriptor specific to the caller's process.
    fd_t map_fd;

    // Original fd as it appears in the eBPF byte code
    // before relocation.
    fd_t original_fd;

    // Original fd of the inner_map.
    fd_t inner_map_original_fd;

    struct bpf_map* inner_map;
    ebpf_map_definition_in_memory_t map_definition;
    char* pin_path;
    bool pinned;
    // Whether this map is newly created or reused
    // from an existing map.
    bool reused;
} ebpf_map_t;

typedef struct bpf_link
{
    char* pin_path;
    ebpf_handle_t handle;
    fd_t fd;
    bool disconnected;
} ebpf_link_t;

typedef struct bpf_object
{
    char* object_name = nullptr;
    std::vector<ebpf_program_t*> programs;
    std::vector<ebpf_map_t*> maps;
    bool loaded = false;
} ebpf_object_t;

/**
 *  @brief Initialize the eBPF user mode library.
 */
uint32_t
ebpf_api_initiate();

/**
 *  @brief Terminate the eBPF user mode library.
 */
void
ebpf_api_terminate();

ebpf_result_t
get_program_info_data(ebpf_program_type_t program_type, _Outptr_ ebpf_program_info_t** program_info);

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program);

void
clean_up_ebpf_programs(_Inout_ std::vector<ebpf_program_t*>& programs);

void
clean_up_ebpf_map(_In_ _Post_invalid_ ebpf_map_t* map);

void
clean_up_ebpf_maps(_Inout_ std::vector<ebpf_map_t*>& maps);

/**
 * @brief Get next eBPF object.
 *
 * @param[in] previous Pointer to previous eBPF object, or NULL to get the first one.
 * @return Pointer to the next object, or NULL if none.
 */
_Ret_maybenull_ struct bpf_object*
ebpf_object_next(_In_opt_ const struct bpf_object* previous);

/**
 * @brief Get next program in ebpf_object object.
 *
 * @param[in] previous Pointer to previous eBPF program, or NULL to get the first one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the next program, or NULL if none.
 */
_Ret_maybenull_ struct bpf_program*
ebpf_program_next(_In_opt_ const struct bpf_program* previous, _In_ const struct bpf_object* object);

/**
 * @brief Get previous program in ebpf_object object.
 *
 * @param[in] next Pointer to next eBPF program, or NULL to get the last one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the previous program, or NULL if none.
 */
_Ret_maybenull_ struct bpf_program*
ebpf_program_previous(_In_opt_ const struct bpf_program* next, _In_ const struct bpf_object* object);

/**
 * @brief Unload an eBPF program.
 *
 * @param[in] program Program to unload.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_program_unload(_In_ struct bpf_program* program);

/**
 * @brief Bind a map to a program so that it holds a reference on the map.
 *
 * @param[in] prog_fd File descriptor of program to bind map to.
 * @param[in] map_fd File descriptor of map to bind.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_program_bind_map(fd_t program_fd, fd_t map_fd);

/**
 * @brief Get next map in ebpf_object object.
 *
 * @param[in] previous Pointer to previous eBPF map, or NULL to get the first one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the next map, or NULL if none.
 */
_Ret_maybenull_ struct bpf_map*
ebpf_map_next(_In_opt_ const struct bpf_map* previous, _In_ const struct bpf_object* object);

/**
 * @brief Get previous map in ebpf_object object.
 *
 * @param[in] next Pointer to next eBPF map, or NULL to get the last one.
 * @param[in] object Pointer to eBPF object.
 * @return Pointer to the previous map, or NULL if none.
 */
_Ret_maybenull_ struct bpf_map*
ebpf_map_previous(_In_opt_ const struct bpf_map* next, _In_ const struct bpf_object* object);

/**
 * @brief Create a new map.
 *
 * @param[in] map_type Type of outer map to create.
 * @param[in] map_name Optionally, the name to use for the map.
 * @param[in] key_size Size in bytes of keys.
 * @param[in] value_size Size in bytes of values.
 * @param[in] max_entries Maximum number of entries in the map.
 * @param[in] opts Structure of options using which a map gets created.
 * @param[out] map_fd File descriptor for the created map. The caller needs to
 *  call _close() on the returned fd when done.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_map_create(
    enum bpf_map_type map_type,
    _In_opt_z_ const char* map_name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _In_opt_ const struct bpf_map_create_opts* opts,
    _Out_ fd_t* map_fd);

/**
 * @brief Fetch fd for a program object.
 *
 * @param[in] program Pointer to eBPF program.
 * @return fd for the program on success, ebpf_fd_invalid on failure.
 */
fd_t
ebpf_program_get_fd(_In_ const struct bpf_program* program);

/**
 * @brief Clean up ebpf_object. Also delete all the sub objects
 * (maps, programs) and close the related file descriptors.
 *
 * @param[in] object Pointer to ebpf_object.
 */
void
ebpf_object_close(_In_opt_ _Post_invalid_ struct bpf_object* object);

void
initialize_map(_Out_ ebpf_map_t* map, _In_ const map_cache_t& map_cache);

/**
 * @brief Pin an eBPF map to specified path.
 * @param[in] program Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_pin(_In_ struct bpf_map* map, _In_opt_z_ const char* path);

/**
 * @brief Unpin an eBPF map from the specified path.
 * @param[in] map Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_unpin(_In_ struct bpf_map* map, _In_opt_z_ const char* path);

/**
 * @brief Set pin path for an eBPF map.
 * @param[in] map Pointer to eBPF map.
 * @param[in] path Pin path for the map.
 *
 * @retval EBPF_SUCCESS The API suceeded.
 * @retval EBPF_NO_MEMORY Out of memory.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_map_set_pin_path(_In_ struct bpf_map* map, _In_opt_z_ const char* path);

/**
 * @brief Update value for the specified key in an eBPF map.
 *
 * @param[in] map_fd File descriptor for the eBPF map.
 * @param[in] key Pointer to buffer containing key, or NULL for a map with no keys.
 * @param[out] value Pointer to buffer containing value.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_update_element(fd_t map_fd, _In_opt_ const void* key, _In_ const void* value, uint64_t flags);

/**
 * @brief Delete an element in an eBPF map.
 *
 * @param[in] map_fd File descriptor for the eBPF map.
 * @param[in] key Pointer to buffer containing key.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_delete_element(fd_t map_fd, _In_ const void* key);

/**
 * @brief Look up an element in an eBPF map.
 *  For a singleton map, return the value for the given key.
 *  For a per-cpu map, return aggregate value across all CPUs.
 *
 * @param[in] map_fd File descriptor for the eBPF map.
 * @param[in] key Pointer to buffer containing key.
 * @param[out] value Pointer to buffer that contains value on success.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_lookup_element(fd_t map_fd, _In_opt_ const void* key, _Out_ void* value);

/**
 * @brief Look up an element in an eBPF map.
 *  For a singleton map, return the value for the given key.
 *  For a per-cpu map, return aggregate value across all CPUs.
 *  On successful lookup, the element is removed from the map.
 *
 * @param[in] map_fd File descriptor for the eBPF map.
 * @param[in] key Pointer to buffer containing key, or NULL for a map with no keys.
 * @param[out] value Pointer to buffer that contains value on success.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_map_lookup_and_delete_element(fd_t map_fd, _In_opt_ const void* key, _Out_ void* value);

/**
 * @brief Return the next key in an eBPF map.
 *
 * @param[in] map_fd File descriptor for the eBPF map.
 * @param[in] previous_key Pointer to buffer containing
    previous key or NULL to restart enumeration.
 * @param[out] next_key Pointer to buffer that contains next
 *  key on success.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MORE_KEYS previous_key was the last key.
 */
ebpf_result_t
ebpf_map_get_next_key(fd_t map_fd, _In_opt_ const void* previous_key, _Out_ void* next_key);

/**
 * @brief Detach a link given a file descriptor.
 *
 * @param[in] fd File descriptor for the link.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_FD The file descriptor was not valid.
 */
ebpf_result_t
ebpf_detach_link_by_fd(fd_t fd);

/**
 * @brief Open a file descriptor for the map with a given ID.
 *
 * @param[in] id ID for the map.
 * @param[out] fd A new file descriptor.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_PARAMETER No such ID found.
 */
ebpf_result_t
ebpf_get_map_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept;

/**
 * @brief Open a file descriptor for the eBPF program with a given ID.
 *
 * @param[in] id ID for the eBPF program.
 * @param[out] fd A new file descriptor.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_PARAMETER No such ID found.
 */
ebpf_result_t
ebpf_get_program_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept;

/**
 * @brief Open a file descriptor for the link with a given ID.
 *
 * @param[in] id ID for the link.
 * @param[out] fd A new file descriptor.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_PARAMETER No such ID found.
 */
ebpf_result_t
ebpf_get_link_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept;

/**
 * @brief Look for the next link ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after.
 * @param[out] next_id The next ID.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MORE_KEYS No more IDs found.
 */
ebpf_result_t
ebpf_get_next_link_id(ebpf_id_t start_id, ebpf_id_t _Out_* next_id) noexcept;

/**
 * @brief Look for the next map ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after.
 * @param[out] next_id The next ID.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MORE_KEYS No more IDs found.
 */
ebpf_result_t
ebpf_get_next_map_id(ebpf_id_t start_id, ebpf_id_t _Out_* next_id) noexcept;

/**
 * @brief Look for the next program ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after.
 * @param[out] next_id The next ID.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MORE_KEYS No more IDs found.
 */
ebpf_result_t
ebpf_get_next_program_id(ebpf_id_t start_id, ebpf_id_t _Out_* next_id) noexcept;

/**
 * @brief Obtain information about the eBPF object referred to by bpf_fd.
 * This function populates up to info_len bytes of info, which will
 * be in one of the following formats depending on the eBPF object type of
 * bpf_fd:
 *
 * * struct bpf_link_info
 * * struct bpf_map_info
 * * struct bpf_prog_info
 *
 * @param[in] bpf_fd File descriptor referring to an eBPF object.
 * @param[out] info Pointer to memory in which to write the info obtained.
 * @param[in,out] info_size On input, contains the maximum number of bytes to
 * write into the info.  On output, contains the actual number of bytes written.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_object_get_info_by_fd(
    fd_t bpf_fd, _Out_writes_bytes_to_(*info_size, *info_size) void* info, _Inout_ uint32_t* info_size);

/**
 * @brief Pin an object to the specified path.
 * @param[in] fd File descriptor to the object.
 * @param[in] path Path to pin the object to.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
ebpf_result_t
ebpf_object_pin(fd_t fd, _In_z_ const char* path);

/**
 * @brief Get fd for a pinned object by pin path.
 * @param[in] path Pin path for the object.
 *
 * @return file descriptor for the pinned object, -1 if not found.
 */
fd_t
ebpf_object_get(_In_z_ const char* path);

/**
 * @brief Open a file without loading the programs.
 *
 * @param[in] path File name to open.
 * @param[in] object_name Optional object name to override file name
 * as the object name.
 * @param[in] pin_root_path Optional root path for automatic pinning of maps.
 * @param[in] program_type Optional program type for all programs.
 * If NULL, the program type is derived from the section names.
 * @param[in] attach_type Default attach type for all programs.
 * If NULL, the attach type is derived from the section names.
 * @param[out] object Returns a pointer to the object created.
 * @param[out] error_message Error message string, which
 * the caller must free using ebpf_free_string().
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_object_open(
    _In_z_ const char* path,
    _In_opt_z_ const char* object_name,
    _In_opt_z_ const char* pin_root_path,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _Outptr_ struct bpf_object** object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept;

/**
 * @brief Load all the programs in a given object.
 *
 * @param[in] object Object from which to load programs.
 * @param[in] execution_type Execution type.
 * @param[out] error_message Error message string, which
 * the caller must free using ebpf_free_string().
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_object_load(
    _Inout_ struct bpf_object* object,
    ebpf_execution_type_t execution_type,
    _Outptr_result_maybenull_z_ const char** error_message);

/**
 * @brief Unload all the programs in a given object.
 *
 * @param[in] object Object in which to unload programs.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
 */
ebpf_result_t
ebpf_object_unload(_In_ struct bpf_object* object);

typedef int (*ring_buffer_sample_fn)(void* ctx, void* data, size_t size);

/**
 * @brief Subscribe for notifications from the input ring buffer map.
 *
 * @param[in] ring_buffer_map_fd File descriptor to the ring buffer map.
 * @param[in] sample_callback_context Pointer to supplied context to be passed in notification callback.
 * @param[in] sample_callback Function pointer to notification handler.
 * @param[out] subscription Opaque pointer to ring buffer subscription object.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Out of memory.
 */
ebpf_result_t
ebpf_ring_buffer_map_subscribe(
    fd_t ring_buffer_map_fd,
    _In_opt_ void* sample_callback_context,
    ring_buffer_sample_fn sample_callback,
    _Outptr_ ring_buffer_subscription_t** subscription);

/**
 * @brief Unsubscribe from the ring buffer map event notifications.
 *
 * @param[in] subscription Pointer to ring buffer subscription to be canceled.
 */
bool
ebpf_ring_buffer_map_unsubscribe(_Inout_ _Post_invalid_ ring_buffer_subscription_t* subscription);

/**
 * @brief Get list of programs and stats in an ELF eBPF file.
 * @param[in] file Name of ELF file containing eBPF program.
 * @param[in] section Optionally, the name of the section to query.
 * @param[in] verbose Obtain additional info about the programs.
 * @param[out] data On success points to a list of eBPF programs.
 * @param[out] error_message On failure points to a text description of
 *  the error.
 */
uint32_t
ebpf_api_elf_enumerate_sections(
    _In_z_ const char* file,
    _In_opt_z_ const char* section,
    bool verbose,
    _Outptr_result_maybenull_ ebpf_section_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message);
