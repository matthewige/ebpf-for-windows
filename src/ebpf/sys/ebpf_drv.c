/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

/*++

Abstract:
WDF based driver that does the following:
1. Registers as a WFP L2 Callout
2. Opens a IOCTL surface

Environment:

    Kernel mode

--*/

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include "ebpf_core.h"
#include "ebpf_l2_hook.h"
#include "ebpf_protocol.h"
#include "ebpf_windows.h"
#include <fwpmk.h>
#include <netiodef.h>

#define RTL_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))

// Driver global variables

static DEVICE_OBJECT* _wdm_device_object;
static BOOLEAN _driver_unloading_flag = FALSE;
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

// Typedefs

typedef VOID(WINAPI* FUNCTION_TYPE)(VOID);
typedef DWORD(WINAPI* FUNCTION_TYPE1)(DWORD);
typedef DWORD(WINAPI* FUNCTION_TYPE2)(PVOID, PVOID);

//
// Constants
//
static const wchar_t EBPF_DEVICE_NAME[] = L"\\Device\\EbpfIoDevice";
static const wchar_t EBPF_SYMBOLIC_DEVICE_NAME[] = L"\\GLOBAL??\\EbpfIoDevice";

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Pre-Declarations
//
static VOID
EbpfCoreEvtIoDeviceControl(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t output_buffer_length,
    _In_ size_t input_buffer_length,
    _In_ ULONG io_control_code);

inline NTSTATUS
ebpf_error_code_to_ntstatus(ebpf_error_code_t error)
{
    switch (error) {
    case EBPF_ERROR_SUCCESS:
        return STATUS_SUCCESS;
    case EBPF_ERROR_OUT_OF_RESOURCES:
        return STATUS_INSUFFICIENT_RESOURCES;
    case EBPF_ERROR_NOT_FOUND:
        return STATUS_NOT_FOUND;
    case EBPF_ERROR_INVALID_PARAMETER:
        return STATUS_INVALID_PARAMETER;
    case EBPF_ERROR_BLOCKED_BY_POLICY:
        // TODO: Find a better erorr code for this.
        return STATUS_NOT_SUPPORTED;
    case EBPF_ERROR_NO_MORE_KEYS:
        return STATUS_NO_MORE_MATCHES;
    case EBPF_ERROR_INVALID_HANDLE:
        return STATUS_INVALID_HANDLE;
    case EBPF_ERROR_NOT_SUPPORTED:
        return STATUS_NOT_SUPPORTED;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD) _IRQL_requires_same_
    _IRQL_requires_max_(PASSIVE_LEVEL) void EvtDriverUnload(_In_ WDFDRIVER driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    _driver_unloading_flag = TRUE;

    ebpf_hook_unregister_callouts();

    ebpf_core_terminate();
}

//
// Create a basic WDF driver, set up the device object
// for a callout driver and setup the ioctl surface
//
static NTSTATUS
EbpfCoreInitDriverObjects(
    _Inout_ DRIVER_OBJECT* driver_object,
    _In_ const UNICODE_STRING* registry_path,
    _Out_ WDFDRIVER* driver,
    _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driver_configuration;
    PWDFDEVICE_INIT device_initialize = NULL;
    WDF_IO_QUEUE_CONFIG io_queue_configuration;
    UNICODE_STRING ebpf_device_name;
    UNICODE_STRING ebpf_symbolic_device_name;
    BOOLEAN device_create_flag = FALSE;

    WDF_DRIVER_CONFIG_INIT(&driver_configuration, WDF_NO_EVENT_CALLBACK);

    driver_configuration.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_configuration.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &driver_configuration, driver);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    device_initialize = WdfControlDeviceInitAllocate(
        *driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL // only kernel/system and admins
    );
    if (!device_initialize) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(device_initialize, FILE_DEVICE_NETWORK);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_DEVICE_SECURE_OPEN, FALSE);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    RtlInitUnicodeString(&ebpf_device_name, EBPF_DEVICE_NAME);
    WdfDeviceInitAssignName(device_initialize, &ebpf_device_name);

    status = WdfDeviceCreate(&device_initialize, WDF_NO_OBJECT_ATTRIBUTES, device);

    if (!NT_SUCCESS(status)) {
        // do not free if any other call
        // after WdfDeviceCreate fails.
        WdfDeviceInitFree(device_initialize);
        device_initialize = NULL;
        goto Exit;
    }

    device_create_flag = TRUE;

    // create symbolic link for control object for um
    RtlInitUnicodeString(&ebpf_symbolic_device_name, EBPF_SYMBOLIC_DEVICE_NAME);
    status = WdfDeviceCreateSymbolicLink(*device, &ebpf_symbolic_device_name);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // parallel default queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&io_queue_configuration, WdfIoQueueDispatchParallel);

    io_queue_configuration.EvtIoDeviceControl = EbpfCoreEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        *device,
        &io_queue_configuration,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE // pointer to default queue
    );
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ebpf_error_code_to_ntstatus(ebpf_core_initiate());
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    WdfControlFinishInitializing(*device);

Exit:
    if (!NT_SUCCESS(status)) {
        if (device_create_flag && device != NULL) {
            //
            // Release the reference on the newly created object, since
            // we couldn't initialize it.
            //
            WdfObjectDelete(*device);
        }
    }
    return status;
}

static VOID
EbpfCoreEvtIoDeviceControl(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t output_buffer_length,
    _In_ size_t input_buffer_length,
    _In_ ULONG io_control_code)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;
    void* input_buffer = NULL;
    void* output_buffer = NULL;
    size_t actual_input_length = 0;
    size_t actual_output_length = 0;
    const struct _ebpf_operation_header* user_request = NULL;
    struct _ebpf_operation_header* user_reply = NULL;

    UNREFERENCED_PARAMETER(output_buffer_length);
    UNREFERENCED_PARAMETER(input_buffer_length);

    device = WdfIoQueueGetDevice(queue);

    switch (io_control_code) {
    case IOCTL_EBPFCTL_METHOD_BUFFERED:
        // Verify that length of the input buffer supplied to the request object
        // is not zero
        if (input_buffer_length != 0) {
            // Retrieve the input buffer associated with the request object
            status = WdfRequestRetrieveInputBuffer(
                request,             // Request object
                input_buffer_length, // Length of input buffer
                &input_buffer,       // Pointer to buffer
                &actual_input_length // Length of buffer
            );

            if (!NT_SUCCESS(status)) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: Input buffer failure %d\n", status));
                goto Done;
            }

            if (input_buffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                goto Done;
            }

            if (input_buffer != NULL) {
                size_t minimum_request_size = 0;
                size_t minimum_reply_size = 0;

                status = ebpf_hook_register_callouts(_wdm_device_object);
                // non fatal for now while testing

                user_request = input_buffer;
                if (actual_input_length < sizeof(struct _ebpf_operation_header)) {
                    status = STATUS_INVALID_PARAMETER;
                    goto Done;
                }

                status = ebpf_error_code_to_ntstatus(ebpf_core_get_protocol_handler_properties(
                    user_request->id, &minimum_request_size, &minimum_reply_size));
                if (status != STATUS_SUCCESS)
                    goto Done;

                // Be aware: Input and output buffer point to the same memory.
                if (minimum_reply_size > 0) {
                    // Retrieve output buffer associated with the request object
                    status = WdfRequestRetrieveOutputBuffer(
                        request, output_buffer_length, &output_buffer, &actual_output_length);
                    if (!NT_SUCCESS(status)) {
                        KdPrintEx(
                            (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: Output buffer failure %d\n", status));
                        goto Done;
                    }
                    if (output_buffer == NULL) {
                        status = STATUS_INVALID_PARAMETER;
                        goto Done;
                    }

                    if (actual_output_length < minimum_reply_size) {
                        status = STATUS_BUFFER_TOO_SMALL;
                        goto Done;
                    }
                    user_reply = output_buffer;
                }

                status = ebpf_error_code_to_ntstatus(ebpf_core_invoke_protocol_handler(
                    user_request->id, user_request, user_reply, (uint16_t)actual_output_length));

                // Fill out the rest of the out buffer after processing the input
                // buffer.
                if (status == STATUS_SUCCESS && user_reply) {
                    user_reply->id = user_request->id;
                    user_reply->length = (uint16_t)actual_output_length;
                }
                goto Done;
            }
        } else {
            status = NDIS_STATUS_INVALID_PARAMETER;
            goto Done;
        }
        break;
    default:
        break;
    }

Done:
    WdfRequestCompleteWithInformation(request, status, output_buffer_length);
    return;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    WDFDRIVER driver;
    WDFDEVICE device;

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: DriverEntry\n"));

    status = EbpfCoreInitDriverObjects(driver_object, registry_path, &driver, &device);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    _wdm_device_object = WdfDeviceWdmGetDeviceObject(device);

    ebpf_hook_register_callouts(_wdm_device_object);
    // ignore status. at boot, registration can fail.
    // we will try to re-register during program load.

Exit:

    if (!NT_SUCCESS(status)) {
        ebpf_hook_unregister_callouts();
    }

    return status;
}
