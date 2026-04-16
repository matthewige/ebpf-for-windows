# Async Processing (Pend/Complete) for eBPF Network Extensions

## Contents
- [Motivation](#motivation)
- [Requirements](#requirements)
- [Design overview](#design-overview)
  - [Custom map for pend state](#custom-map-for-pend-state)
  - [Extension helper functions](#extension-helper-functions)
  - [Map key and value structures](#map-key-and-value-structures)
  - [Example eBPF program usage](#example-ebpf-program-usage)
- [PEND flow](#pend-flow)
- [COMPLETE flow](#complete-flow)
- [CONTINUE flow](#continue-flow)
- [Failure flows](#failure-flows)
- [Edge case and failure handling](#edge-case-and-failure-handling)
- [Internal pend state tracking](#internal-pend-state-tracking)
- [Multiple attached programs and PEND](#multiple-attached-programs-and-pend)
- [WFP implementation requirements](#wfp-implementation-requirements)
- [Consumer integration guide](#consumer-integration-guide)
- [ebpfcore platform requirements](#ebpfcore-platform-requirements)
- [netebpfext work breakdown](#netebpfext-work-breakdown)

## Motivation

Network callout drivers often need to defer a verdict on a connection or
packet while waiting for an asynchronous decision from another component
-- for example, a user-mode policy service or a kernel-mode classification
driver. The Windows Filtering Platform (WFP) provides `FwpsPendOperation`
/ `FwpsCompleteOperation` to support this pattern at ALE authorize layers,
but eBPF programs running through netebpfext currently have no way to
express "pend this operation and complete it later."

This proposal adds **pend/complete (async processing) support** to
netebpfext, enabling eBPF programs to:
1. **PEND** a network operation -- absorb a connection/packet while an
   external consumer makes a decision asynchronously.
2. **COMPLETE** the pended operation with a verdict (PERMIT, BLOCK, or
   CONTINUE -- re-invoke the program for continued evaluation; the
   program starts a fresh invocation, not a mid-execution resume).

The design is generic: any consumer (kernel-mode driver, user-mode
service, or both) can integrate with pend/complete by interacting with
eBPF maps and optional BTF-resolved functions. No changes to the
consumer's notification or decision-delivery mechanism are prescribed by
netebpfext itself.

> **Design status:** This document describes a proposed design. The map
> types, helper functions, and structures shown here are planned
> interfaces and are not yet implemented.

## Requirements

### Functional requirements
1. An eBPF program attached to an ALE authorize hook point (CONNECT or
   RECV_ACCEPT) must be able to pend the current network operation and
   return control to WFP.
2. An external consumer must be able to complete the pended operation
   with a verdict (PERMIT, BLOCK, or CONTINUE) at a later time.
3. The CONTINUE verdict must re-invoke the eBPF program so it can
   resume evaluation from where it left off.
4. The pend/complete mechanism must be fully encapsulated within
   netebpfext -- eBPF programs and consumers interact only through
   maps and helper functions; no WFP-specific details leak to callers.

### Supported WFP layers
The initial implementation targets the **ALE CONNECT** and **ALE
RECV_ACCEPT** layers (`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and
`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`).

Full plan-of-record (POR) for pend/complete support:

| Layer | WFP layer IDs | Status |
|-------|---------------|--------|
| Connect (outbound) | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | Initial target |
| Accept (inbound) | `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` | Initial target |
| Bind | `FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6` | Future POR |
| Listen | `FWPM_LAYER_ALE_AUTH_LISTEN_V4/V6` | Future POR |
| Stream/datagram application protocol rules (e.g., DNS filtering) | TBD | Future POR |

Future layers may introduce layer-specific differences in map metadata
and WFP completion semantics.

### Non-requirements
- The notification mechanism between the eBPF program and the consumer
  is **not** part of this proposal. Consumers are responsible for
  choosing how to deliver pend notifications and receive verdicts (see
  [Consumer integration guide](#consumer-integration-guide)).
- Only one program in a multi-program chain may PEND a given connection
  (see [Multiple attached programs and PEND](#multiple-attached-programs-and-pend)).

## Design overview

### Custom map for pend state
The design leverages the
[custom map](https://github.com/microsoft/ebpf-for-windows/pull/4882)
feature. Custom maps allow an eBPF extension to register as an NMR
provider for a custom map type and intercept CRUD operations on map
entries. The extension's callbacks are invoked **synchronously** and
**serialized per map** (ebpfcore acquires a per-map lock before invoking
the extension's callback) -- when the eBPF program inserts into the map,
the extension's `process_map_add_element` callback runs inline before
the call returns. Similarly, when a user-mode process updates or
deletes a map entry (via `bpf_map_update_elem` / `bpf_map_delete_elem`),
the extension's callbacks are invoked synchronously through ebpfcore.

This provides a data communication mechanism between netebpfext (which
implements pend/complete semantics via `FwpsPendOperation` /
`FwpsCompleteOperation`) and the consumer (which reacts to the pend
and issues a verdict once finished).

> **Note:** Custom map types require adding a new enum value to
> `ebpf_map_type_t` in `ebpf_structs.h`, which means a change to the
> eBPF-for-Windows repository is needed.

> **Note:** The custom map framework in ebpf-for-windows currently
> only supports lookup operations from user mode and eBPF helpers.
> This design requires **full CRUD support** for extension-initiated
> custom map operations (from kernel mode, outside an eBPF helper
> call). The extension (netebpfext) must be able to:
> - **Create/insert**: The `pend()` helper inserts the initial map
>   entry.
> - **Update**: After `FwpsPendOperation()` succeeds, the extension
>   stores the `completionContext`, cloned NBL, and reinject
>   parameters into the entry's internal tracking state.
> - **Read/lookup**: The `complete()` helper and CONTINUE
>   flow look up entries by key.
> - **Delete**: Cleanup when `FwpsPendOperation()` fails, when the
>   program returns a non-PEND verdict after calling `pend()`, and
>   after completion.
>
> Additionally, the COMPLETE path from user mode requires
> `bpf_map_update_elem` and `bpf_map_delete_elem` to invoke the
> extension's `process_map_add_element` and
> `process_map_delete_element` callbacks, which are not currently
> wired up for custom maps.

> **Note:** Pend maps must have the same namespace isolation properties
> as regular eBPF maps. The eBPF-for-Windows namespace proposal
> ([PR #4424](https://github.com/microsoft/ebpf-for-windows/pull/4424))
> defines the isolation model for eBPF objects. The custom map
> framework must support namespace properties so that only processes
> within the same namespace can look up, update, or delete pend map
> entries -- ensuring that the user-mode process that loaded the
> program and created the map is the only one that can issue COMPLETE
> operations.

### Extension helper functions

The extension exposes two helper functions:

1. **`net_ebpf_ext_pend_operation()`** -- called by the eBPF program to
   pend the current connection. Generates an opaque key, populates the
   map entry, and returns the key to the caller. No WFP pend calls are
   made here -- `FwpsPendOperation()` is called later by netebpfext
   after the program returns the PEND verdict.

2. **`net_ebpf_ext_complete_operation()`** -- called by the eBPF program
   during CONTINUE re-invocation to deliver a final verdict (PERMIT or
   BLOCK) for a previously pended connection. Internally, it calls
   `bpf_map_update_elem` (to store the verdict) then
   `bpf_map_delete_elem` (to trigger WFP completion via
   `process_map_delete_element`), routing through the same single
   completion path as the normal COMPLETE flow.

The eBPF program calls `pend()`, which populates an opaque key and
inserts the entry into the pend map. The program treats the key as
opaque bytes -- it can pass the key to an external consumer (e.g., via
a BTF-resolved function or a shared map) and the consumer echoes it back
for the COMPLETE path. During CONTINUE re-invocation, the program calls
`complete()` to deliver the final verdict. This keeps all WFP
implementation details fully encapsulated within the extension.

The actual `FwpsPendOperation()` call is made by netebpfext *after* the
eBPF program returns with the PEND verdict, while still within the WFP
classify callback context (where the `completionHandle` from the
classify metadata is still valid). The `pend()` helper itself only
generates the key, populates the map entry, and returns -- no WFP pend
calls. If the program returns a non-PEND verdict after calling `pend()`,
netebpfext automatically cleans up the map entry -- no WFP calls are
needed since the operation was never pended.

### Map key and value structures

#### Map key
The map key is **opaque to callers**. The extension generates and
manages the key internally. Programs and consumers pass the key through
without interpreting its contents. Both the key and value structures
include an `ebpf_extension_header_t` as their first field, following
the standard eBPF for Windows versioning convention (see
`ebpf_windows.h`). This allows new fields to be appended in future
versions without breaking backward compatibility.

```c
// Opaque key structure -- callers must not interpret or construct these fields.
// The extension populates this via net_ebpf_ext_pend_operation() and returns it to the caller.
// Versioned using the standard ebpf_extension_header_t pattern (see ebpf_windows.h).
typedef struct _net_ebpf_ext_pend_key {
    ebpf_extension_header_t header;     // Version/size header for forward compatibility
    uint64_t pend_id;                   // Monotonic counter generated by the extension
} net_ebpf_ext_pend_key_t;
```

> The map key uses a monotonic counter (`pend_id`) rather than the
> `completionContext`, because `FwpsPendOperation()` is called after
> the program returns -- the program needs the key earlier (to include
> in any notification to the consumer). The `completionContext` is
> stored in the entry's internal tracking state after
> `FwpsPendOperation()` succeeds.

#### Map value
The map value has a **minimum prefix** defined by the extension: a
single `action` field that the extension reads to distinguish a new
PEND insertion from a COMPLETE update (PERMIT/BLOCK). Callers may
declare a larger value type with additional fields after this prefix --
the extension only accesses the prefix. The extension also appends its
own internal tracking fields (WFP layer ID, lifecycle state) after
the caller's value using the extension-controlled value size feature --
these are not visible to callers on lookups.

```c
typedef enum _net_ebpf_ext_pend_action {
    NET_EBPF_EXT_PEND_ACTION_PENDING = 0,   // Operation is pended, awaiting consumer decision
    NET_EBPF_EXT_PEND_ACTION_PERMIT = 1,    // Consumer verdict: permit
    NET_EBPF_EXT_PEND_ACTION_BLOCK = 2,     // Consumer verdict: block
    NET_EBPF_EXT_PEND_ACTION_CONTINUE = 3,  // Consumer verdict: re-invoke program to continue evaluation
} net_ebpf_ext_pend_action_t;

// Minimum value prefix required by the extension.
// Programs may embed this in a larger value struct to store additional metadata.
// Versioned using the standard ebpf_extension_header_t pattern (see ebpf_windows.h).
typedef struct _net_ebpf_ext_pend_value {
    ebpf_extension_header_t header;     // Version/size header for forward compatibility
    net_ebpf_ext_pend_action_t action;  // Set to PENDING by pend; read by extension on COMPLETE/CONTINUE
} net_ebpf_ext_pend_value_t;
```

#### Map type
```c
// Custom map type for pend/complete operations (value TBD, must be added to ebpf_structs.h)
#define BPF_MAP_TYPE_NET_EBPF_EXT_PEND <TBD>  // To be defined in ebpf_map_type_t enum
```

#### Extension helper function prototypes
```c
// Pends the current connection by inserting an entry into the pend map.
// The extension generates a unique key (monotonic counter), sets
// action = PENDING in the value prefix, appends internal tracking
// state (WFP layer ID, lifecycle flags) after the caller's value,
// and inserts the entry. No WFP pend calls are made here --
// FwpsPendOperation() is called later by netebpfext after the program
// returns the PEND verdict.
// On success, the opaque key is returned in *key for the caller to
// pass through to the consumer. The helper also stores the key
// and map pointer in the private/extended portion of the program
// context (ctx) so that netebpfext's classify wrapper can retrieve
// them after the program returns -- the wrapper needs the key and map
// to look up the entry and store the completionContext, cloned NBL,
// and reinject parameters.
// The caller should set any caller-specific fields in *value before calling.
// value:     Pointer to the caller's value buffer. Must start with the
//            net_ebpf_ext_pend_value_t prefix (action field). Callers may
//            include additional fields after the prefix.
// value_size: Size of the caller's value buffer in bytes.
int net_ebpf_ext_pend_operation(_In_ void* ctx,
                               _In_ void* pend_map,
                               _Out_ net_ebpf_ext_pend_key_t* key,
                               _In_reads_bytes_(value_size) void* value,
                               uint32_t value_size);
```

```c
// Completes a previously pended connection with the given verdict.
// Internally, this helper performs two map operations:
//   1. bpf_map_update_elem (stores the verdict in the action field)
//   2. bpf_map_delete_elem (triggers FwpsCompleteOperation() via the
//      extension's process_map_delete_element callback)
// This ensures all completions -- whether initiated by the eBPF
// program (CONTINUE -> final verdict) or by the management process
// (normal COMPLETE) -- follow the same single code path through
// process_map_delete_element, which runs under the per-map lock
// and guarantees serialization of the per-processor pending
// completion context.
// This is used by the eBPF program during CONTINUE re-invocation when
// the program reaches a final PERMIT or BLOCK verdict.
// Returns: 0 on success, negative error code on failure (entry not found,
//          already completed, map operation failed, etc.).
int net_ebpf_ext_complete_operation(_In_ void* pend_map,
                                   _In_ const net_ebpf_ext_pend_key_t* key,
                                   net_ebpf_ext_pend_action_t verdict);
```

### Example eBPF program usage
```c
// Consumer-defined extended pend map value -- embeds the extension-required
// prefix and adds consumer-specific fields.
typedef struct _my_pend_map_value {
    net_ebpf_ext_pend_value_t base;     // Extension-required prefix (action)
    uint64_t consumer_context;          // Consumer-defined context (e.g., client ID, rule ID)
    uint64_t timestamp;                 // Set by program at pend time; used for stale-entry expiration
} my_pend_map_value_t;

struct {
    __uint(type, BPF_MAP_TYPE_NET_EBPF_EXT_PEND);
    __type(key, net_ebpf_ext_pend_key_t);
    __type(value, my_pend_map_value_t);
    __uint(max_entries, 1024);
} pend_map SEC(".maps");

// ... in program logic:
net_ebpf_ext_pend_key_t opaque_key = {};
my_pend_map_value_t value = {};

value.consumer_context = /* consumer-defined identifier */;
value.timestamp = bpf_ktime_get_boot_ns();

int err = net_ebpf_ext_pend_operation(ctx, &pend_map, &opaque_key, &value, sizeof(value));
if (err != 0) {
    return DEFAULT_VERDICT;
}

// Notify the consumer about the pended operation.
// This is consumer-specific -- could be a BTF-resolved function call,
// a write to a shared map, or any other mechanism.
// The consumer needs the opaque_key to issue the COMPLETE later.
int notify_result = notify_consumer(ctx, &opaque_key, /* ... */);
if (notify_result != 0) {
    // Notification failed -- return non-PEND verdict.
    // netebpfext automatically cleans up the map entry.
    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

return BPF_SOCK_ADDR_VERDICT_PEND;
```

## PEND flow
1. The eBPF extension registers as a custom map provider (NMR provider
   for the Map Information NPI), defining the pend map type.
2. The eBPF program declares a map of this custom type to hold pended
   connections.
3. When the eBPF program determines that a connection needs to be
   pended:
    1. The program populates the caller-visible value, then calls
       `net_ebpf_ext_pend_operation(ctx, &pend_map, &opaque_key, &value, sizeof(value))`
       -- an extension helper function exposed by netebpfext. The
       extension generates a unique key (monotonic counter), sets
       `action = PENDING` in the value prefix, appends internal
       tracking state (WFP layer ID, lifecycle flags) after the
       caller's value, and inserts the entry into the map. The opaque
       key is returned to the caller.
    2. The program notifies the consumer about the pended operation
       (using a consumer-specific mechanism -- see
       [Consumer integration guide](#consumer-integration-guide)),
       passing the opaque key so the consumer can issue a COMPLETE
       later.
        - This notification must be synchronous so the eBPF program
          can handle failure inline (by returning a non-PEND verdict).
        - **If notification fails:** The eBPF program returns a
          non-PEND verdict (e.g., BLOCK). netebpfext detects that the
          program returned a non-PEND verdict after calling `pend()`
          and automatically removes the map entry -- no explicit
          cleanup by the program is needed.
    3. The eBPF program returns the `BPF_SOCK_ADDR_VERDICT_PEND`
       verdict. netebpfext sees this verdict and retrieves the pend
       map key and map pointer from the private/extended portion of
       the program context (stored there by the `pend()` helper). It
       then calls `FwpsPendOperation()` using the `completionHandle`
       from the classify metadata. If successful, it stores the
       returned `completionContext` in the map entry's internal
       tracking state, clones the original NBL (also stored in
       internal state), captures the WFP classify parameters needed
       for reinject (endpoint handle, addresses, interface indexes,
       etc. -- see internal state struct), and sets
       `FWP_ACTION_BLOCK` with `FWPS_CLASSIFY_OUT_FLAG_ABSORB` in
       the classifyOut -- telling WFP the operation is absorbed
       (pended). The NBL clone is needed for both layers: CONNECT
       reinjects it after reauth permits via
       `FwpsInjectTransportSendAsync`; RECV_ACCEPT reinjects it via
       `FwpsInjectTransportReceiveAsync` after
       `FwpsCompleteOperation` completes the authorization.
        - **If `FwpsPendOperation()` succeeds:** The operation is now
          pended in WFP. The map entry exists for the later COMPLETE
          path.
        - **If `FwpsPendOperation()` fails:** netebpfext removes the
          map entry and returns a BLOCK verdict to WFP. The
          notification has already been sent, but when the consumer
          eventually tries to COMPLETE, the map entry will not exist
          and the COMPLETE will fail gracefully (see COMPLETE flow
          below).

```
participant "tcpip.sys" as tcpip
participant "netebpfext.sys" as ebpfext
participant "ebpfcore.sys" as ebpfcore
participant "eBPF Program" as bpfprog
participant "Consumer" as consumer

tcpip->ebpfext: Network event\n(WFP callout)
ebpfext->ebpfcore: Invoke eBPF program
ebpfcore->bpfprog: Execute program
bpfprog->bpfprog: Process rules, determine pend needed

bpfprog->ebpfext: net_ebpf_ext_pend_operation(ctx, &pend_map,\n&opaque_key, &value, sizeof(value))\n(extension helper)
ebpfext->ebpfext: Generate key (monotonic counter),\npopulate internal tracking,\ninsert into map
ebpfext->bpfprog: Return success + opaque key

bpfprog->consumer: Notify consumer\n(consumer-specific mechanism,\npasses opaque_key)
consumer->bpfprog: Return success

bpfprog->ebpfcore: Return PEND verdict
ebpfcore->ebpfext: Return PEND verdict
ebpfext->ebpfext: Call FwpsPendOperation(completionHandle),\nclone NBL, save reinject params,\nstore completionContext in entry
ebpfext->tcpip: Return FWP_ACTION_BLOCK + ABSORB\n(operation pended)
```

## COMPLETE flow

> **Important:** `FwpsCompleteOperation()` is **only** invoked inside the
> `process_map_delete_element` callback -- that is, completion occurs
> exclusively when a map entry is deleted via `bpf_map_delete_elem`.
> netebpfext does not initiate completion on its own for any error state
> or edge case. All error and edge-case handling (consumer timeout,
> consumer crash, stale entries, program unload, etc.) must be driven by
> the user-mode management process (the process that loaded the eBPF
> program and created the map), which is responsible for issuing the
> appropriate `bpf_map_update_elem` + `bpf_map_delete_elem` calls to
> resolve each pending entry. For CONTINUE (re-invoke the program), the
> management process calls `bpf_map_update_elem` only -- no delete --
> see [CONTINUE flow](#continue-flow).
>
> **Completion behavior (layer-dependent):** `FwpsCompleteOperation()`
> behavior differs by WFP layer:
> - **CONNECT (outbound):** `FwpsCompleteOperation(ctx, NULL)` triggers
>   synchronous reauthorization -- the classifyFn fires inline on the
>   same thread with `FWP_CONDITION_FLAG_IS_REAUTHORIZE`. The delete
>   callback stores the verdict in a **per-processor pending
>   completion context** (a per-CPU array slot indexed by
>   `KeGetCurrentProcessorNumber()`) before calling
>   `FwpsCompleteOperation()`. The reauth classifyFn reads the
>   verdict from the same slot (same processor, same thread).
>   The slot is cleared after `FwpsCompleteOperation()` returns.
>   If the verdict is **PERMIT**, the callout queues a threaded DPC to
>   reinject the cloned NBL via `FwpsInjectTransportSendAsync` (the
>   threaded DPC fires only after the classifyFn thread returns,
>   ensuring the pending flag clears before the reinjected packet
>   arrives -- see WFP requirement 12). If **BLOCK**, the cloned NBL
>   is freed.
> - **RECV_ACCEPT (inbound):** `FwpsCompleteOperation(ctx, NULL)`
>   completes the pended authorization. No reauthorization fires.
>   For PERMIT, the callout queues a threaded DPC to reinject the
>   cloned NBL via `FwpsInjectTransportReceiveAsync`.
>   **Note:** The pending-flag / reinject race (WFP requirement 12)
>   has been confirmed on the CONNECT layer, where
>   `FwpsCompleteOperation` may return before the internal pending
>   flag is fully cleared. An analogous race may exist on the
>   RECV_ACCEPT receive-inject path -- `FwpsCompleteOperation`
>   returns void on both layers, and there is no documented
>   guarantee that the flag is cleared synchronously. The threaded
>   DPC is used here as a precaution: it adds negligible cost and
>   ensures reinject does not fire until the classifyFn thread
>   returns, matching the CONNECT behavior. This should be
>   validated during implementation.
>   For BLOCK, the cloned NBL is freed. The cloned NBL was saved
>   in internal state at pend time.

1. The consumer makes its decision and delivers the verdict to the
   user-mode management process (the process that loaded the eBPF
   program and owns the pend map).
2. For **PERMIT or BLOCK**, the management process uses the opaque
   pend key echoed back from the consumer and performs two map
   operations:
   1. **Update verdict**: Call `bpf_map_update_elem` with `BPF_EXIST`
      to write the verdict (permit/block/continue) into the entry's
      `action` field. The extension's `process_map_add_element`
      callback validates that the action is `PERMIT`, `BLOCK`, or
      `CONTINUE` (not `PENDING`). For PERMIT/BLOCK, this stores the
      verdict for the subsequent delete. For CONTINUE, the extension
      queues a work item to re-invoke the program (see
      [CONTINUE flow](#continue-flow)). If the entry does not exist
      (e.g., `FwpsPendOperation()` failed and the entry was cleaned
      up, or the stale-connection timeout removed it),
      `bpf_map_update_elem` returns an error.
   2. **Delete entry**: Call `bpf_map_delete_elem` with the same key.
      The extension's `process_map_delete_element` callback reads the
      stored verdict from the `action` field and calls
      `FwpsCompleteOperation()`:
      - **CONNECT:** Stores the verdict in the per-processor
        pending completion context, calls
        `FwpsCompleteOperation(ctx, NULL)`. The reauth classifyFn
        fires synchronously on the same thread, reads the verdict
        from the per-processor slot, and returns it to WFP
        (`FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`). After
        `FwpsCompleteOperation()` returns, the slot is cleared.
        If the verdict is **PERMIT**, a threaded DPC is queued to
        reinject the cloned NBL via `FwpsInjectTransportSendAsync`.
        If **BLOCK**, the cloned NBL is freed. Then the entry is
        removed from the map.
      - **RECV_ACCEPT:** Calls
        `FwpsCompleteOperation(ctx, NULL)` to complete the pended
        authorization. If the verdict is **PERMIT**, a threaded DPC
        is queued to reinject the cloned NBL via
        `FwpsInjectTransportReceiveAsync`. If **BLOCK**, the cloned
        NBL is freed. After completion and reinject (if applicable),
        the entry is removed.
3. The management process checks the return values. On success,
   the operation is complete. On failure (entry not found on update,
   or delete fails), it reports the failure to the consumer.
   netebpfext does not perform any error handling or recovery for
   COMPLETE operations -- it returns error codes via the standard map
   API return values, and all error handling is the responsibility of
   the management process.

```
participant "Consumer" as consumer
participant "Management Process" as mgmt
participant "ebpfcore.sys" as ebpfcore
participant "netebpfext.sys" as ebpfext
participant "tcpip.sys" as tcpip

consumer->mgmt: Deliver verdict\n(opaque_key, verdict)

mgmt->mgmt: Build pend map value\nwith verdict (permit/block)
mgmt->ebpfcore: bpf_map_update_elem(&pend_map,\n&opaque_key, &value, BPF_EXIST)
ebpfcore->ebpfext: process_map_add_element callback
ebpfext->ebpfext: Validate action is PERMIT or BLOCK
ebpfext->ebpfcore: Return success
ebpfcore->mgmt: Map update success\n(verdict stored)

mgmt->ebpfcore: bpf_map_delete_elem(&pend_map,\n&opaque_key)
ebpfcore->ebpfext: process_map_delete_element callback

alt Entry found (normal COMPLETE)
ebpfext->ebpfext: Read stored verdict,\nverify not already completed

alt CONNECT (outbound)
ebpfext->ebpfext: Store verdict in per-processor\npending completion context
ebpfext->tcpip: FwpsCompleteOperation(completionContext, NULL)\n(triggers synchronous reauthorization)

note over tcpip,ebpfext: Reauth fires inline (same thread)

tcpip->ebpfext: classifyFn callback\n(FWP_CONDITION_FLAG_IS_REAUTHORIZE)
ebpfext->ebpfext: Read verdict from per-processor\npending completion context
ebpfext->tcpip: Return stored verdict\n(FWP_ACTION_PERMIT or FWP_ACTION_BLOCK)
note over tcpip,ebpfext: FwpsCompleteOperation returns

alt PERMIT
ebpfext->ebpfext: Queue threaded DPC to reinject cloned NBL
note over ebpfext: Threaded DPC fires:
ebpfext->tcpip: FwpsInjectTransportSendAsync(clonedNbl)
else BLOCK
ebpfext->ebpfext: Free cloned NBL
end

else RECV_ACCEPT (inbound) -- PERMIT
ebpfext->tcpip: FwpsCompleteOperation(completionContext, NULL)\n(completes authorization)
ebpfext->ebpfext: Queue threaded DPC to reinject cloned NBL
note over ebpfext: Threaded DPC fires:
ebpfext->tcpip: FwpsInjectTransportReceiveAsync(clonedNbl)

else RECV_ACCEPT (inbound) -- BLOCK
ebpfext->tcpip: FwpsCompleteOperation(completionContext, NULL)\n(connection blocked)
ebpfext->ebpfext: Free cloned NBL
end

ebpfext->ebpfext: Remove map entry
ebpfcore->mgmt: Map delete success
mgmt->consumer: Complete succeeded
else Entry not found (pend failed or timed out)
ebpfext->ebpfcore: Return error
ebpfcore->mgmt: Map delete failed
mgmt->consumer: Complete failed
end
```

## CONTINUE flow

When the consumer responds with CONTINUE (instead of PERMIT or BLOCK),
the pended connection is not yet decided. Instead, the eBPF program is
re-invoked to resume evaluation from where it left off. The program may
then return a final verdict (PERMIT/BLOCK) or PEND again for another
round of async processing.

CONTINUE differs from COMPLETE in two key ways:
1. **No map delete**: The management process calls
   `bpf_map_update_elem` with `action = CONTINUE` but does **not**
   call `bpf_map_delete_elem`. The pend map entry stays alive --
   `FwpsCompleteOperation()` is not called, and the WFP connection
   remains pended.
2. **Program re-invocation**: The extension queues a worker thread that
   re-invokes the eBPF program using a saved program context, allowing
   the program to continue its evaluation.

### Saved state for continuation

Two categories of state must be preserved to support CONTINUE:

**a) eBPF program context (saved by the extension):**
At pend time, the extension must save a copy of the eBPF program
context (e.g., `bpf_sock_addr_t`) in the internal tracking state.
The program context is constructed from the WFP classify parameters
(fixed values, metadata, layer data), which are stack-based and only
valid during the original `classifyFn` call -- once `FwpsPendOperation()`
is called and the callback returns, they are gone. The saved program
context allows the extension to re-invoke the program for CONTINUE
without needing the original WFP parameters.

**b) Program evaluation state (saved by the eBPF program):**
The eBPF program needs to store its evaluation resume point -- e.g.,
which rule was being evaluated, which filter node in the tree, any
intermediate results, and the opaque pend key (for re-PEND
notifications). This state is stored by the program in a **separate
regular hash map** (not the pend map) keyed by a connection identifier
the program can derive from the `sock_addr` context (e.g., the
5-tuple: protocol, local address, local port, remote address, remote
port).

The separate map is necessary because the pend map key is opaque -- the
program cannot derive it from context on re-invocation. A regular hash
map keyed by connection tuple gives the program a stable lookup key
that is available in both the original and continuation invocations.
The program checks this map on **every invocation** -- if an entry
exists, it is a continuation; otherwise it is a fresh invocation.

```c
// Example: program-managed continuation state map
typedef struct _my_continuation_state {
    uint32_t rule_index;                // Resume point (consumer-defined)
    uint32_t sub_index;                 // Position within rule evaluation
    net_ebpf_ext_pend_key_t pend_key;   // Opaque key for re-PEND or COMPLETE
    // ... additional evaluation state as needed
} my_continuation_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, bpf_sock_addr_t);       // Connection tuple (or a hash/subset of it)
    __type(value, my_continuation_state_t);
    __uint(max_entries, 1024);
} continuation_map SEC(".maps");
```

### CONTINUE flow steps

1. The consumer responds with CONTINUE. The management process calls
   `bpf_map_update_elem` with `action = CONTINUE` on the pend map
   entry. The extension's `process_map_add_element` callback validates
   the action and records the CONTINUE request.
2. The extension detects the CONTINUE action and queues a work item
   (the callback runs under the per-map lock -- re-invocation cannot
   happen inline because the eBPF program may perform map operations
   such as `complete()`, which calls `bpf_map_update_elem` +
   `bpf_map_delete_elem`, and those would deadlock trying to
   re-acquire the same per-map lock). The pend map entry remains --
   no delete, no `FwpsCompleteOperation()`. The action is reset to
   `PENDING`.
3. The work item fires on a worker thread. The extension re-invokes
   the eBPF program through ebpfcore using the saved program context.
   netebpfext's classify wrapper runs in this context -- the same
   wrapper that handles the normal classify path. This means all
   post-program logic is active: the re-PEND guard
   (`lifecycle_state` check), orphaned map entry cleanup (non-PEND
   verdict after `pend()`), and context extraction. The only
   difference is that there is no live WFP classifyFn context, so
   `FwpsPendOperation()` is not called (the operation is already
   pended) and classifyOut is not set.
4. The eBPF program checks the continuation map (keyed by connection
   tuple from `sock_addr` context). An entry exists, so the program
   resumes evaluation from the saved position.
5. The program evaluates and returns one of:
   - **PERMIT or BLOCK**: The program calls
     `net_ebpf_ext_complete_operation(&pend_map, &pend_key, verdict)`
     using the opaque key retrieved from its continuation map. The
     helper internally calls `bpf_map_update_elem` (to store the
     verdict) then `bpf_map_delete_elem` (to trigger WFP completion
     via `process_map_delete_element`). This routes through the same
     single completion path as the normal COMPLETE flow, ensuring
     serialization under the per-map lock. The pend map entry is
     removed after completion. The program cleans up its continuation
     map entry and returns a non-PEND verdict.
   - **PEND**: The program hit another point requiring async
     processing. The program updates its continuation state in the
     continuation map (including the stored opaque key), sends a new
     notification to the consumer using the stored key, and returns
     PEND. The entry remains in the pend map. The extension detects
     that `FwpsPendOperation()` was already called (via
     `lifecycle_state` in internal tracking) and skips re-calling it.

> **Note:** On CONTINUE re-invocation, the extension must not call
> `FwpsPendOperation()` again if the program returns PEND, since the WFP
> operation is already pended (`FwpsPendOperation()` cannot be called
> during reauthorization, and the operation is still pended from the
> original call). The `lifecycle_state` field in the internal tracking
> state provides this guard.

```
participant "Consumer" as consumer
participant "Management Process" as mgmt
participant "ebpfcore.sys" as ebpfcore
participant "netebpfext.sys" as ebpfext
participant "eBPF Program" as bpfprog
participant "tcpip.sys" as tcpip

note over consumer: Consumer decides: CONTINUE\n(resume program evaluation)

consumer->mgmt: Deliver verdict\n(opaque_key, CONTINUE)

mgmt->ebpfcore: bpf_map_update_elem(&pend_map,\n&opaque_key, &value{action=CONTINUE}, BPF_EXIST)
ebpfcore->ebpfext: process_map_add_element callback
ebpfext->ebpfext: Validate CONTINUE action,\nreset action to PENDING,\nqueue work item
ebpfext->ebpfcore: Return success
ebpfcore->mgmt: Map update success

note over ebpfext: Work item fires on worker thread

ebpfext->ebpfcore: Invoke eBPF program\n(using saved program context)
ebpfcore->bpfprog: Execute program

bpfprog->bpfprog: Check continuation map\n(keyed by connection tuple)\nEntry found -- resume evaluation

bpfprog->bpfprog: Continue evaluation\nfrom saved position

alt Program reaches final verdict (PERMIT/BLOCK)
bpfprog->ebpfext: net_ebpf_ext_complete_operation(\n&pend_map, &pend_key, verdict)
ebpfext->ebpfext: bpf_map_update_elem\n(store verdict in action field)
ebpfext->ebpfext: bpf_map_delete_elem\n(triggers process_map_delete_element)
note over ebpfext: Same completion path as\nnormal COMPLETE flow\n(serialized under per-map lock)
ebpfext->ebpfext: process_map_delete_element:\nFwpsCompleteOperation + reinject/free
ebpfext->bpfprog: Return success
bpfprog->bpfprog: Clean up continuation map entry
bpfprog->ebpfcore: Return non-PEND verdict
ebpfcore->ebpfext: Return
note over ebpfext: Connection finalized

else Program needs to pend again (re-PEND)
bpfprog->bpfprog: Update continuation map\n(new resume point + stored pend key)
bpfprog->consumer: Notify consumer\n(using stored pend key)
consumer->bpfprog: Return success
bpfprog->ebpfcore: Return PEND verdict
ebpfcore->ebpfext: Return PEND verdict
ebpfext->ebpfext: lifecycle_state already PENDED\n-- skip FwpsPendOperation()\n(cannot re-pend during reauth)
note over ebpfext: Entry remains in pend map,\nawaiting next consumer response
end
```

## Failure flows

### Notification fails
```
participant "netebpfext.sys" as ebpfext
participant "eBPF Program" as bpfprog
participant "Consumer" as consumer

note over bpfprog: pend() succeeded (entry in map)

bpfprog->consumer: Notify consumer\n(consumer-specific mechanism)
consumer->bpfprog: Return error

note over bpfprog: Notification failed -- return BLOCK

bpfprog->ebpfext: Return REJECT verdict
note over ebpfext: netebpfext sees non-PEND verdict\nafter pend() was called --\nautomatically removes map entry
note over bpfprog: No pend occurred -- connection blocked normally
```

### FwpsPendOperation() fails after program returns PEND
```
participant "tcpip.sys" as tcpip
participant "netebpfext.sys" as ebpfext
participant "ebpfcore.sys" as ebpfcore
participant "eBPF Program" as bpfprog

note over bpfprog: pend() and notification both succeeded

bpfprog->ebpfcore: Return PEND verdict
ebpfcore->ebpfext: Return PEND verdict
ebpfext->ebpfext: Call FwpsPendOperation() -- fails

note over ebpfext: Pend failed -- remove map entry, return BLOCK

ebpfext->ebpfext: Remove map entry
ebpfext->tcpip: Return BLOCK verdict

note over ebpfext: Consumer was notified but will get\na graceful failure when it tries to COMPLETE
```

## Edge case and failure handling

### 1. Stale pended connections (COMPLETE never arrives)

A pended connection may never be completed for various reasons: the
consumer crashes, the management process is unavailable, or the consumer
simply takes too long to respond. In all cases, the pend map entry
remains and the WFP connection stays pended indefinitely.

There are three layers of protection against stale entries:

**a) Management process age-based timer (primary cleanup):**
The management process (which loaded the eBPF program and owns the pend
map) runs a periodic timer that enumerates pend map entries and expires
entries that have exceeded an age threshold (using a `timestamp` field
in the caller-visible value, set by the eBPF program at pend time). For
each expired entry, the process calls `bpf_map_delete_elem` -- the
extension's `process_map_delete_element` callback defaults to BLOCK when
no verdict is stored (`action = PENDING`). For **CONNECT**, this calls
`FwpsCompleteOperation(ctx, NULL)`, triggering synchronous reauth where
the classifyFn returns BLOCK, then the cloned NBL is freed. For
**RECV_ACCEPT**, this calls `FwpsCompleteOperation(ctx, NULL)`, dropping
the packet, then the cloned NBL is freed. This is the primary cleanup
mechanism for stale entries.

**b) Management process proactive cleanup (consumer disconnection):**
When a consumer crashes or disconnects, the management process detects
this (via its own IPC mechanism) and enumerates the pend map entries,
identifies entries belonging to that consumer (using a consumer-defined
field in the caller-visible value), and issues `bpf_map_delete_elem`
for each. Since the entry's `action` field is still `PENDING` (no
verdict was set), the extension's `process_map_delete_element` callback
defaults to BLOCK and calls `FwpsCompleteOperation()` accordingly.

**c) Management process crash (no active cleanup possible):**
If the management process itself crashes, there is no user-mode process
available to issue map operations or run timers. Stale entries remain
until the management process restarts and resumes its timer-based
cleanup. A future improvement could add a watchdog or kernel-mode
cleanup callback.

**d) Program unload (management-process-driven drain):**
If the eBPF program needs to be unloaded (e.g., policy update or
shutdown), the management process must first drain all pending
connections. The process enumerates the pend map, sets the `action`
field to the desired verdict via `bpf_map_update_elem`, and then issues
`bpf_map_delete_elem` for each entry -- triggering the normal COMPLETE
flow via `process_map_delete_element`. Only after all pending entries
have been drained should the process proceed with program unload.

### 2. Pend entry lifecycle edge cases

A pended entry can be affected by operations happening out of the
expected order. Two key scenarios:

**a) Entry removed via unexpected delete:**
Since `bpf_map_delete_elem` now triggers `FwpsCompleteOperation()` in
the `process_map_delete_element` callback, most unintended deletions are
safe -- the extension defaults to BLOCK when no verdict is stored
(`action = PENDING`). However, some edge cases remain:
- The stale-connection timer (item #1 above) races with a legitimate
  COMPLETE and deletes the entry first. The subsequent delete from the
  management process fails gracefully (entry not found).
- If the eBPF program is unloaded or replaced, the management process
  must drain all pending entries first (see item #1d above). The process
  should not allow program unload while pend map entries remain.

**b) Duplicate COMPLETE attempts:**
Nothing prevents the management process from calling
`bpf_map_delete_elem` twice for the same key (e.g., retry logic,
duplicate messages, or a race with the stale-connection timer). The
second call fails because the entry no longer exists (the first delete
removed it), so the process receives an error -- no risk of calling
`FwpsCompleteOperation()` twice.

### 3. Program returns non-PEND verdict after calling pend()
If the eBPF program calls `net_ebpf_ext_pend_operation()` (which inserts
the map entry) but then returns a non-PEND verdict (e.g., because
notification failed), a map entry exists but `FwpsPendOperation()` was
never called (it only runs after a PEND verdict). netebpfext
automatically detects this: when the program returns a non-PEND verdict
after `pend()` was called during the same invocation, netebpfext simply
removes the orphaned map entry. No WFP calls are needed since the
operation was never pended. No explicit cleanup by the eBPF program is
needed -- returning a non-PEND verdict is sufficient.

## Internal pend state tracking

The edge cases above require netebpfext to track per-entry WFP
lifecycle state. The extension uses the **extension-controlled value
size** feature to store internal tracking fields alongside the
caller-visible map value. When the extension inserts an entry (via the
`pend()` helper), it writes a larger value than what callers declared --
the caller-visible value (the caller's declared struct) followed by
extension-private tracking fields. On lookups, the extension only
returns the caller-visible portion.

The extension tracks the following internal state per entry:

- The WFP layer ID (CONNECT vs RECV_ACCEPT) -- determines completion
  behavior (synchronous reauth for CONNECT vs no reauth for RECV_ACCEPT)
- The `completionContext` returned by `FwpsPendOperation()` (set after
  the program returns PEND; used by `FwpsCompleteOperation()` later)
- Whether `FwpsPendOperation()` has been called for the entry
- A cloned NBL to reinject on completion (CONNECT reinjects via
  `FwpsInjectTransportSendAsync`; RECV_ACCEPT reinjects via
  `FwpsInjectTransportReceiveAsync`)
- Saved WFP classify parameters needed for reinject -- these are only
  valid during classifyFn and must be captured at pend time:
  - **Common**: `addressFamily`, `compartmentId`
  - **CONNECT (outbound)**: `endpointHandle`, `remoteAddress`,
    `remoteScopeId`, `controlData`/`controlDataLength` (for
    `FwpsInjectTransportSendAsync` send parameters)
  - **RECV_ACCEPT (inbound)**: `interfaceIndex`, `subInterfaceIndex`,
    `ipHeaderSize`, `transportHeaderSize` (for NBL offset adjustment
    and `FwpsInjectTransportReceiveAsync` parameters)
- A saved copy of the eBPF program context (e.g., `bpf_sock_addr_t`),
  constructed from the WFP classify parameters at pend time, needed
  for CONTINUE re-invocation
- The aggregate verdict from programs that ran before the PEND program
  in the multi-program chain (for combining on COMPLETE)

The internal tracking fields are appended after the caller-visible
value:

```c
// Lifecycle state for a pend map entry. Tracks the WFP pend/complete
// progress to handle the race where COMPLETE arrives before
// FwpsPendOperation() is called.
typedef enum _net_ebpf_ext_pend_lifecycle {
    NET_EBPF_EXT_PEND_LIFECYCLE_STORED = 0,           // Map entry created, FwpsPendOperation() not yet called
    NET_EBPF_EXT_PEND_LIFECYCLE_PENDED = 1,           // FwpsPendOperation() succeeded, waiting for verdict
    NET_EBPF_EXT_PEND_LIFECYCLE_VERDICT_RECEIVED = 2, // Verdict arrived before FwpsPendOperation() (race)
} net_ebpf_ext_pend_lifecycle_t;

// Internal tracking fields appended after the caller-visible value.
// Not exposed to callers -- the extension controls the actual stored value size.
// On lookups, only the caller-visible portion is returned.
typedef struct _net_ebpf_ext_pend_internal_state {
    uint16_t layer_id;                  // WFP layer ID (CONNECT vs RECV_ACCEPT) -- determines completion behavior
    HANDLE completion_context;          // Returned by FwpsPendOperation(); used by FwpsCompleteOperation()
    net_ebpf_ext_pend_lifecycle_t lifecycle_state; // Entry lifecycle (STORED -> PENDED -> completed, or STORED -> VERDICT_RECEIVED if race)
    uint32_t aggregate_verdict;         // Aggregate verdict from prior programs in the chain
    PNET_BUFFER_LIST cloned_nbl;        // Cloned NBL for reinjection (CONNECT: FwpsInjectTransportSendAsync; RECV_ACCEPT: FwpsInjectTransportReceiveAsync)

    // Saved classify parameters for reinject (only valid during classifyFn -- captured at pend time).
    ADDRESS_FAMILY address_family;      // AF_INET or AF_INET6
    COMPARTMENT_ID compartment_id;      // Network compartment
    union {
        struct {                        // CONNECT (outbound) reinject parameters
            UINT64 endpoint_handle;     // Transport endpoint handle (from inMetaValues)
            UINT8 remote_address[16];   // Remote address (from inFixedValues), sized for IPv6
            SCOPE_ID remote_scope_id;   // Remote scope ID (from inMetaValues)
            WSACMSGHDR* control_data;   // Control data (from inMetaValues, allocated copy)
            ULONG control_data_length;  // Control data length
        } connect;
        struct {                        // RECV_ACCEPT (inbound) reinject parameters
            IF_INDEX interface_index;   // Delivery interface index (from inFixedValues)
            IF_INDEX sub_interface_index; // Delivery sub-interface index (from inFixedValues)
            ULONG ip_header_size;       // IP header size (from inMetaValues)
            ULONG transport_header_size; // Transport header size (from inMetaValues)
        } recv_accept;
    } reinject_params;

    // Saved eBPF program context for CONTINUE re-invocation:
    // e.g., bpf_sock_addr_t constructed from WFP classify parameters at pend time.
    // (Actual fields TBD -- depends on the program type and context struct.)
} net_ebpf_ext_pend_internal_state_t;
```

The actual value stored in the map is: `[caller-visible value] + [internal state]`.
For example, with a consumer-defined `my_pend_map_value_t` as the
caller-declared value:
`[my_pend_map_value_t] + [net_ebpf_ext_pend_internal_state_t]`.

The lifecycle of the internal state:
- **Created** when `net_ebpf_ext_pend_operation()` inserts the map entry.
  `lifecycle_state` is set to `STORED`. `completion_context` is NULL.
- **Updated** when `FwpsPendOperation()` succeeds (after the program
  returns PEND): sets `lifecycle_state = PENDED`, stores
  `completion_context`. The cloned NBL is stored for both layers.
  The WFP classify parameters needed for reinject (endpoint handle,
  addresses, interface indexes, header sizes, etc.) are also captured
  since they are only available during classifyFn.
- **Updated** when `FwpsCompleteOperation()` is called. For
  **CONNECT**, reauth fires synchronously within this call, then the
  entry is removed from the pend map. For **RECV_ACCEPT**, the entry
  is removed immediately after `FwpsCompleteOperation()` returns.
- **Removed** if the program returns a non-PEND verdict after
  `pend()` (just remove the entry -- no WFP calls needed since the
  operation was never pended), or if `FwpsPendOperation()` fails
  after the program returns PEND (remove entry, return BLOCK).

This state enables the following protections:

**For stale connections (item #1):** The management process runs a
periodic timer that enumerates pend map entries using the `timestamp`
field in the caller-visible value. For each stale entry, the process
calls `bpf_map_delete_elem`, which triggers the extension's
`process_map_delete_element` callback to call
`FwpsCompleteOperation(ctx, NULL)` with a BLOCK verdict (CONNECT:
synchronous reauth returning BLOCK; RECV_ACCEPT: completes the
authorization), frees the cloned NBL, and removes the entry. The
management process has access to pend maps because it is the user-mode
process that loaded the eBPF program and created the map.

**For lifecycle edge cases (item #2):**
- `process_map_delete_element` (COMPLETE path): Read the stored `action`
  field -- if `PERMIT` or `BLOCK`, use that verdict; if still `PENDING`
  (no verdict set, e.g., cleanup paths), default to BLOCK. Verify the
  entry has not already been completed, then call
  `FwpsCompleteOperation()`:
  - **CONNECT:** Store verdict in the per-processor pending
    completion context, call `FwpsCompleteOperation(ctx, NULL)`.
    Reauth fires inline -- the classifyFn reads the verdict from
    the per-processor slot and returns it. If PERMIT, queue a
    threaded DPC to reinject the cloned NBL via
    `FwpsInjectTransportSendAsync`. If BLOCK, free the cloned NBL.
  - **RECV_ACCEPT:** Call `FwpsCompleteOperation(ctx, NULL)`. For
    PERMIT, queue a threaded DPC to reinject the cloned NBL via
    `FwpsInjectTransportReceiveAsync`. For BLOCK, free the cloned NBL.
- `process_map_add_element` (verdict update): Validate that the action
  is `PERMIT`, `BLOCK`, or `CONTINUE` (not `PENDING`). For
  PERMIT/BLOCK, store the verdict for the subsequent delete. For
  CONTINUE, queue a work item to re-invoke the program using saved
  WFP context (see [CONTINUE flow](#continue-flow)) and reset action
  to PENDING. If the entry no longer exists (already completed),
  return an error.
- `process_map_delete` (map destruction): In normal operation, the
  management process drains all pending entries before program unload
  (see item #1d), so this callback should find no entries. As a
  defensive measure, call `FwpsCompleteOperation()` for any remaining
  pended entries (BLOCK verdict -- CONNECT via synchronous reauth then
  free cloned NBL, RECV_ACCEPT via
  `FwpsCompleteOperation(ctx, NULL)` then free cloned NBL) and log a
  warning.

### Race condition: COMPLETE arrives before `FwpsPendOperation()` is called (optional)

The eBPF program sends the notification *before* returning the PEND
verdict and before `FwpsPendOperation()` is called. It is theoretically
possible for the consumer (on another CPU) to receive the notification,
process it, and issue a COMPLETE -- triggering `FwpsCompleteOperation()`
via the delete callback -- before netebpfext has called
`FwpsPendOperation()`. In practice, this is extremely unlikely since the
PEND path completes with in-kernel function returns (nanoseconds) while
the COMPLETE path crosses to user mode and back (multiple context
switches). However, under CPU preemption or heavy load, it could occur.

The delete callback can detect this: `lifecycle_state` is still
`STORED` (and `completion_context` is NULL). Rather than calling
`FwpsCompleteOperation()` (which requires a valid `completionContext`),
the callback saves the verdict in the entry and transitions to a
**VERDICT_RECEIVED** state. When `FwpsPendOperation()` later succeeds,
netebpfext checks for this state and immediately queues a worker thread
to call `FwpsCompleteOperation()` with the saved verdict.

**Mitigation:** The `lifecycle_state` field in the internal tracking
state implements a per-entry state machine with three states:

| State | Meaning |
|-------|---------|
| `STORED` | Map entry created, `FwpsPendOperation()` not yet called |
| `PENDED` | `FwpsPendOperation()` succeeded, waiting for consumer verdict |
| `VERDICT_RECEIVED` | Consumer verdict arrived before `FwpsPendOperation()` was called (race detected -- verdict is saved) |

In the normal case: `pend()` -> **STORED** -> PEND verdict returns
-> `FwpsPendOperation()` -> **PENDED** -> COMPLETE update + delete ->
`FwpsCompleteOperation()` -> (CONNECT: reauth inline; RECV_ACCEPT:
packet delivered/dropped) -> entry removed.

In the race case: `pend()` -> **STORED** -> COMPLETE update + delete
(early!) -> save verdict -> **VERDICT_RECEIVED** -> PEND verdict
returns -> `FwpsPendOperation()` -> netebpfext sees VERDICT_RECEIVED
-> **worker thread** -> `FwpsCompleteOperation()` -> (CONNECT: reauth;
RECV_ACCEPT: packet delivered/dropped) -> entry removed.

Note that `FwpsCompleteOperation()` must not be called within the
same `classifyFn` context. WFP uses a refcount on the pend auth
context: the classify stack holds one ref, and `FwpsPendOperation`
takes a second. If `FwpsCompleteOperation` is called while classifyFn
is still on the stack, it decrements the refcount from 2 to 1 -- not
to 0 -- so `operationComplete` (reauth for CONNECT, packet delivery
for RECV_ACCEPT) does **not** fire. It fires later, when classifyFn
returns and the classify teardown drops the last ref. At that point,
the per-processor pending completion context slot has already been
cleared, so the reauth classifyFn would find an empty slot. To
avoid this, the VERDICT_RECEIVED path must defer
`FwpsCompleteOperation()` to a work item that runs after classifyFn
returns -- ensuring refcount drops to 0 inside
`FwpsCompleteOperation()` and the reauth fires inline while the
per-processor slot is still populated.

## Multiple attached programs and PEND

> **Note:** Pend/complete with a single program is already a complex
> scenario involving custom maps, WFP lifecycle management, worker
> threads, and cross-component coordination. Supporting multiple
> programs each independently PENDing the same connection would add
> significantly more complexity (saving/restoring state for each
> remaining program, coordinating multiple pending entries per
> connection, resolving conflicts between concurrent async decisions).
> To avoid this complexity, **only one program in the chain may PEND a
> given connection**.

netebpfext currently supports **up to 16 programs** on multi-attach
hook points (e.g., ALE CONNECT) and **1 program** on single-attach
hook points (e.g., ALE RECV_ACCEPT). Programs are invoked in attach
order, and verdicts are combined using a **"most restrictive wins"**
policy -- REJECT (highest priority) > PROCEED_HARD > PROCEED_SOFT
(lowest). If any program returns REJECT, the chain exits early and
subsequent programs are skipped.

**PEND behaves as an early exit**, similar to REJECT:

1. Programs 1..N-1 run and their verdicts are aggregated normally.
2. Program N returns `BPF_SOCK_ADDR_VERDICT_PEND`. The chain stops --
   programs N+1..M are **not** invoked.
3. The aggregate verdict from programs 1..N-1 is saved in the pend map
   entry's internal tracking state (as `aggregate_verdict`).
4. On COMPLETE, the PEND program's final verdict (PERMIT or BLOCK) is
   combined with the saved aggregate using the same max-priority
   logic. The combined result is used as the verdict for
   `FwpsCompleteOperation()` -- for CONNECT, this is returned via
   synchronous reauth; for RECV_ACCEPT, it determines whether the
   cloned NBL is reinjected (PERMIT) or freed (BLOCK). Both layers
   call `FwpsCompleteOperation(ctx, NULL)`.

Since prior programs can only have returned permissive verdicts
(REJECT would have stopped the chain before reaching the PEND
program), the PEND program's verdict will always dominate or tie the
aggregate. This preserves the existing verdict combining semantics
with no changes to the combining logic itself -- only the aggregate
must be persisted and retrieved.

Programs after the PEND program never run for that connection. This is
consistent with the existing early-exit model -- the PEND program
effectively claims the final decision for the connection.

## WFP implementation requirements

The async processing design relies on several WFP-specific contracts
that the implementation must honor. These are not part of the design
itself but are critical correctness requirements for the WFP callout
driver code.

> **Reference implementation:** The WFP DDK sample
> [`inspect_threadedDPC`](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
> demonstrates the pend/complete pattern with clone-reinject at the
> ALE authorize layers. It is the closest available reference for the
> netebpfext implementation and should be used as a starting point.
>
> **API fragility warning:** The `FwpsPendOperation` /
> `FwpsCompleteOperation` API surface at the ALE authorize layers is
> fragile and under-documented. Known issues include:
> - **Non-TCP reinjection race (day-0 bug):** After
>   `FwpsCompleteOperation` returns, the flow may still be marked as
>   pending internally. If the callout calls
>   `FwpsInjectTransportSendAsync` immediately, tcpip.sys finds the
>   flow still pended and correctly drops the reinjected packet. The
>   DDK sample calls this a "day 0 race in all non-TCP pended auths."
>   `FwpsCompleteOperation` returns void with no out parameter, so the
>   caller has no way to know whether the authorization actually
>   completed. The DDK sample works around this by using a threaded
>   DPC (queued per-CPU, fires only after the classifyFn thread
>   returns to PASSIVE). A system work item (`IoQueueWorkItem`)
>   does **not** provide the same guarantee -- it runs on an
>   arbitrary worker thread that could execute before
>   `FwpsCompleteOperation` finishes clearing the pending flag on
>   the current CPU. The implementation should use a threaded DPC
>   (matching the DDK sample) to defer the reinject call.
> - **Two-callout bypass (non-TCP):** When two callouts are present,
>   the second callout can be bypassed entirely. During
>   `FwpsCompleteOperation`-triggered reauth, the second callout
>   should return BLOCK (to see the reinjected packet for its own
>   authorization). When it does, the connection entry is removed and
>   the reinjected packet goes through full authorization. But if the
>   first callout's `FwpsInjectTransportSendAsync` fires *before* the
>   second callout's classifyFn returns BLOCK, tcpip finds the
>   existing connection entry, determines no reauthorization is
>   needed, and sends the packet without invoking the second callout.
>   This is independent of the non-TCP race above. The threaded DPC
>   workaround avoids both races.
> - **Reinject requirements are implicit:** The documentation for
>   `FwpsCompleteOperation` states that the callout "must reinject the
>   packet that was cloned at that layer" for RECV_ACCEPT, and that
>   "pended packet data is flushed" for both layers -- but does not
>   provide explicit guidance on the reinject API to use, the timing
>   relative to `FwpsCompleteOperation`, or the NBL ownership model.
> - **No proper fix exists:** A proper solution likely requires a new
>   WFP API with a waterfall model. Until then, the threaded DPC
>   workaround is the only known mitigation.
>
> The DDK API reference pages for
> [`FwpsPendOperation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0)
> and
> [`FwpsCompleteOperation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteoperation0)
> should be consulted alongside the sample during implementation.

1. **`FWPS_RIGHT_ACTION_WRITE` check**: Before setting
   `classifyOut->actionType`, the classifyFn must verify that
   `classifyOut->rights & FWPS_RIGHT_ACTION_WRITE` is set. If a
   higher-weight callout has already cleared write rights, the callout
   must not override the action.

2. **Clear write rights on BLOCK**: When returning
   `FWP_ACTION_BLOCK`, the classifyFn must clear
   `classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE` to prevent
   lower-weight callouts from overriding the block.

3. **NBL reference at pend time**: The classifyFn must call
   `FwpsReferenceNetBufferList(nbl, TRUE)` before returning with
   `FWP_ACTION_BLOCK` + `FWPS_CLASSIFY_OUT_FLAG_ABSORB` to keep the
   original NBL alive past classifyFn return. The corresponding
   `FwpsDereferenceNetBufferList(nbl)` must be called after the cloned
   NBL is created (or on error cleanup). The clone itself
   (`FwpsAllocateCloneNetBufferList`) must happen before classifyFn
   returns while the NBL is still valid. This applies to both
   CONNECT and RECV_ACCEPT layers.

4. **`FWPS_METADATA_FIELD_COMPLETION_HANDLE` assertion**: Before calling
   `FwpsPendOperation`, verify that the `completionHandle` is present
   via `FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
   FWPS_METADATA_FIELD_COMPLETION_HANDLE)`. This field should always be
   present at ALE authorize layers -- assert rather than fail silently.

5. **Safety net for leaked completion contexts**: When a pend map entry
   is destroyed and `lifecycle_state >= PENDED`, the cleanup path must
   call `FwpsCompleteOperation(completionContext, NULL)` defensively
   before freeing the entry. This handles cases where the map is
   destroyed (e.g., program unload) before a verdict is issued.

6. **Policy-triggered reauth handling** (CONNECT only): The reauth
   classifyFn must distinguish between completion-triggered reauth and
   policy-triggered reauth. Check
   `FWP_CONDITION_FLAG_IS_REAUTHORIZE` in `incomingValue` and look for
   `FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION`. If reauth
   was triggered by policy change (not completion), do not read from
   the per-processor pending completion context -- fall through to
   normal classify logic instead.

7. **IRQL requirements**: All ALE classify callbacks run at
   `PASSIVE_LEVEL`. `FwpsPendOperation` and `FwpsCompleteOperation` can
   be called at `IRQL <= DISPATCH_LEVEL`. The delete callback (which
   calls `FwpsCompleteOperation`) runs under the ebpfcore map lock at
   `PASSIVE_LEVEL`, so no IRQL concerns for the current design.

8. **BLOCK NBL free order**: When the verdict is BLOCK, call
   `FwpsCompleteOperation()` first to release WFP state, then free the
   cloned NBL. For RECV_ACCEPT, call
   `FwpsCompleteOperation(ctx, NULL)` -- WFP does not take ownership
   when NULL is passed. For CONNECT, reauth fires first (returning
   `FWP_ACTION_BLOCK`), then free the cloned NBL after
   `FwpsCompleteOperation()` returns.

9. **Injection handle**: The driver must create an injection handle via
   `FwpsInjectionHandleCreate` (with `AF_INET`/`AF_INET6` and
   `FWPS_INJECTION_TYPE_TRANSPORT`) at initialization time. This handle
   is used for `FwpsInjectTransportSendAsync` (CONNECT PERMIT) and
   `FwpsInjectTransportReceiveAsync` (RECV_ACCEPT PERMIT). The handle
   must be destroyed via `FwpsInjectionHandleDestroy` at driver unload.

10. **Self-injection check**: The classifyFn must call
    `FwpsQueryPacketInjectionState(injectionHandle, layerData, NULL)`
    when `layerData` is non-NULL and permit the packet immediately if
    the state is `FWPS_PACKET_INJECTED_BY_SELF` or
    `FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF`. Without this check,
    reinjected packets would be re-inspected by the same callout,
    potentially causing infinite loops or spurious re-pend attempts.

11. **Cannot pend during reauthorization**: `FwpsPendOperation` returns
    `STATUS_FWP_CANNOT_PEND` if called during a reauthorization
    classify. This means re-PEND after CONTINUE requires the
    worker-thread approach (see [CONTINUE flow](#continue-flow)).

12. **Reinject deferral via threaded DPC**: The reinject call
    (`FwpsInjectTransportSendAsync` / `FwpsInjectTransportReceiveAsync`)
    must **not** be called inline from `FwpsCompleteOperation` or the
    reauth classifyFn. The race between `FwpsCompleteOperation`
    returning and the flow's internal pending flag being cleared means
    an immediate reinject can be dropped by tcpip.sys. The DDK sample
    uses a **threaded DPC** (`KeInsertQueueDpc`) queued per-CPU during
    the reauth classifyFn -- the DPC fires only after the classifyFn
    thread returns, ensuring the pending flag has been cleared. A
    system work item (`IoQueueWorkItem`) runs on an arbitrary worker
    thread and does not provide this per-CPU ordering guarantee.
    The implementation should follow the DDK sample and use a threaded
    DPC for reinject deferral.

### WFP API sequence (pend and complete)

The following sequence describes the WFP API calls for the pend/complete
flow. The per-layer differences (CONNECT synchronous reauth vs.
RECV_ACCEPT no reauth) and the reinject requirements apply throughout.

1. `FwpsPendOperation(completionHandle)` -- called by netebpfext
   after the eBPF program returns the PEND verdict, while still
   in the classifyFn context. The `completionHandle` is obtained
   from the `FWPS_INCOMING_METADATA_VALUES` passed to classifyFn.
   Returns a `completionContext` that is stored in the pend map
   entry's internal tracking state.
2. The extension clones the original NBL (stored in internal tracking
   state) for both layers -- both need it for reinject after
   completion (CONNECT via `FwpsInjectTransportSendAsync`,
   RECV_ACCEPT via `FwpsInjectTransportReceiveAsync`).
3. ClassifyFn returns `FWP_ACTION_BLOCK` with
   `FWPS_CLASSIFY_OUT_FLAG_ABSORB` -- tells WFP the operation is
   pended (absorbed, not actually blocked).
4. `FwpsCompleteOperation(completionContext, NULL)` -- called
   during the COMPLETE path (from the `process_map_delete_element`
   callback). Behavior differs by layer:
   - **CONNECT:** Triggers synchronous reauthorization -- the
     classifyFn fires inline on the same thread. The callout
     returns the stored verdict. If PERMIT, a threaded DPC is
     queued to reinject the cloned NBL via
     `FwpsInjectTransportSendAsync`.
   - **RECV_ACCEPT:** No reauthorization fires. For PERMIT, a
     threaded DPC is queued to reinject the cloned NBL via
     `FwpsInjectTransportReceiveAsync`. For BLOCK, the cloned
     NBL is freed.
5. **CONNECT only:** Reauthorization classifyFn fires synchronously
   with `FWP_CONDITION_FLAG_IS_REAUTHORIZE` and
   `FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION`. The
   callout returns the stored verdict. The callout must also handle
   policy-triggered reauth (not caused by our completion) -- if no
   matching pending entry is found, pass through with
   `FWP_ACTION_PERMIT`.

### Per-layer completion behavior summary

| Aspect | CONNECT (outbound) | RECV_ACCEPT (inbound) |
|--------|-------------------|----------------------|
| `FwpsCompleteOperation` triggers reauth | Yes (synchronous, inline) | No |
| Verdict delivery mechanism | Reauth classifyFn returns stored verdict via per-processor slot | No reauth; authorization completes directly |
| PERMIT reinject API | `FwpsInjectTransportSendAsync` (threaded DPC) | `FwpsInjectTransportReceiveAsync` (threaded DPC) |
| BLOCK behavior | Reauth returns `FWP_ACTION_BLOCK`; free cloned NBL | `FwpsCompleteOperation(ctx, NULL)`; free cloned NBL |
| Why reinject is needed | Original packet absorbed at pend time; UDP has no retransmit, TCP SYN retransmit has delay | Pended packet data flushed by WFP |

## Consumer integration guide

This section describes what a consumer needs to implement to use the
pend/complete feature. The pend/complete mechanism in netebpfext is
**consumer-agnostic** -- it provides the WFP lifecycle management, map
infrastructure, and extension helpers. The consumer is responsible for:
1. Delivering pend notifications to the decision-maker
2. Receiving verdicts and driving the COMPLETE path via map operations
3. Cleaning up stale entries

### Architecture

A consumer integration has three components:

| Component | Role | Required |
|-----------|------|----------|
| **eBPF program** | Calls `pend()`, notifies consumer, returns PEND verdict | Yes |
| **Consumer** | Receives pend notification, makes async decision, returns verdict | Yes |
| **Management process** | Loads/owns the eBPF program and pend map; drives COMPLETE and cleanup via map operations | Yes |

The **consumer** and **management process** may be the same process or
separate processes. For example, a user-mode service could serve as both
the management process (loading programs, owning maps) and the consumer
(making pend/complete decisions).

### Notification mechanisms

The eBPF program must notify the consumer when a connection is pended.
The notification must be **synchronous** (the program needs the return
value to decide whether to proceed with PEND or fall back). Two
approaches are available:

#### Option A: BTF-resolved function (kfunc)

The consumer's kernel-mode driver registers as a BTF-resolved function
provider (see
[BtfResolvedFunctions.md](BtfResolvedFunctions.md)),
exposing a notification function. The eBPF program calls this function
directly, passing the opaque pend key and any consumer-specific context.

```c
// Example: consumer-provided BTF-resolved function for pend notification.
// The consumer driver registers this via NMR as a BTF-resolved function provider.
int notify_pend(_In_reads_bytes_(info_size) const void* pend_info,
                uint32_t info_size);
```

**Advantages:**
- Synchronous, low-latency (direct kernel function call)
- The consumer driver can queue the notification to user mode via its
  own IPC mechanism (e.g., Filter Manager ports, IOCTLs, named pipes)
- Consumer-specific notification data stays within the consumer's
  control

**Requirements:**
- Consumer must have a kernel-mode driver that registers as a
  BTF-resolved function provider
- Driver must be loaded before the eBPF program (NMR binding dependency)
- Function prototypes must be published to the eBPF registry

#### Option B: Shared map

The eBPF program writes notification data (including the opaque pend
key) to a regular eBPF map (e.g., `BPF_MAP_TYPE_RINGBUF` or
`BPF_MAP_TYPE_HASH`). The management process polls or receives events
from this map and delivers the notification to the consumer.

```c
// Example: notification via ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} notification_ringbuf SEC(".maps");

typedef struct _pend_notification {
    net_ebpf_ext_pend_key_t pend_key;
    uint64_t consumer_context;
    // ... additional fields as needed
} pend_notification_t;
```

**Advantages:**
- No kernel-mode driver required for the consumer
- Works with pure user-mode consumers
- Uses standard eBPF map APIs

**Disadvantages:**
- Higher latency (map write + user-mode poll/event)
- Not truly synchronous from the eBPF program's perspective -- the
  program writes to the map and returns PEND without confirmation that
  the consumer received the notification. If the ring buffer is full,
  the write fails and the program can fall back to a non-PEND verdict.
- The management process must poll or use a callback mechanism to
  detect new entries

#### Choosing an approach

| Criterion | BTF-resolved function | Shared map |
|-----------|----------------------|------------|
| Consumer has kernel driver | Preferred | Possible |
| Consumer is pure user-mode | Not possible | Required |
| Notification latency | Nanoseconds | Microseconds+ |
| Synchronous confirmation | Yes | No (best-effort) |
| Kernel driver dependency | Yes | No |

### COMPLETE path (consumer responsibility)

Regardless of the notification mechanism, the COMPLETE path is always
driven by the **management process** using standard eBPF map APIs:

1. The consumer makes its decision and delivers the verdict (PERMIT,
   BLOCK, or CONTINUE) plus the opaque pend key to the management
   process.
2. The management process calls `bpf_map_update_elem(&pend_map,
   &opaque_key, &value, BPF_EXIST)` to store the verdict in the map
   entry's `action` field.
3. For PERMIT or BLOCK: the management process calls
   `bpf_map_delete_elem(&pend_map, &opaque_key)` to trigger WFP
   completion.
4. For CONTINUE: no delete -- the extension handles program
   re-invocation (see [CONTINUE flow](#continue-flow)).
5. The management process checks the return values and reports
   success/failure back to the consumer.

### Cleanup responsibilities

The management process is responsible for all cleanup:

| Scenario | Required action |
|----------|----------------|
| **Stale entries** | Run a periodic timer; enumerate pend map; delete entries older than threshold |
| **Consumer crash** | Detect disconnection; enumerate pend map; delete entries belonging to that consumer |
| **Program unload** | Drain all pending entries (update verdict + delete) before unloading |
| **Management process restart** | On startup, enumerate pend map and clean up any leftover entries from prior session |

The management process can identify entries belonging to a specific
consumer using consumer-defined fields in the caller-visible portion of
the map value (e.g., a consumer ID or session ID).

### Minimal consumer integration checklist

1. Define a consumer-extended pend map value type (embedding
   `net_ebpf_ext_pend_value_t` as the prefix).
2. Choose a notification mechanism (BTF-resolved function or shared
   map).
3. Implement the notification path in the eBPF program.
4. Implement the COMPLETE path in the management process (map update +
   delete).
5. Implement stale-entry cleanup (periodic timer in management
   process).
6. Implement consumer-crash cleanup (management process detects
   disconnection and drains entries).
7. If using CONTINUE: implement continuation state management in the
   eBPF program (separate hash map keyed by connection tuple).
8. Test failure paths: notification failure, `FwpsPendOperation()`
   failure, stale entry expiration, duplicate COMPLETE, management
   process restart.

## ebpfcore platform requirements

The following changes to ebpfcore are required to support this design:

1. Add the `BPF_MAP_TYPE_NET_EBPF_EXT_PEND` enum value to
   `ebpf_map_type_t` in `ebpf_structs.h`.
2. Add support for custom map update and delete callbacks
   (`process_map_add_element` and `process_map_delete_element` for
   user-mode operations). The COMPLETE path uses `bpf_map_update_elem`
   to store the verdict and `bpf_map_delete_elem` to trigger WFP
   completion via the extension's callbacks.
3. Add support for extension-initiated custom map operations (create,
   read, update, delete) from kernel mode, outside an eBPF helper
   call. The pend/complete design requires the extension to insert
   entries (in the `pend()` helper), update entries (storing
   `completionContext`, cloned NBL, and reinject parameters after
   `FwpsPendOperation()`), read entries (in `complete()` and
   CONTINUE), and delete entries (`FwpsPendOperation()` failure,
   non-PEND verdict after `pend()`, post-completion cleanup).
4. Ensure custom maps support namespace isolation
   ([PR #4424](https://github.com/microsoft/ebpf-for-windows/pull/4424))
   so that only processes within the same namespace can access pend
   map entries.

Note: The general ebpfcore/platform custom map support is already
implemented (lookup only). Items 2 and 3 above extend this to full
CRUD for both user-mode and extension-initiated operations.

## netebpfext work breakdown

1. Implement WFP pend/complete support (call `FwpsPendOperation` /
   `FwpsCompleteOperation` at the appropriate WFP layers, handle
   layer-dependent completion: synchronous reauthorization for CONNECT
   with verdict returned via classifyFn, and
   `FwpsCompleteOperation(ctx, NULL)` for RECV_ACCEPT with no reauth).
   Both layers reinject the cloned NBL on PERMIT via the appropriate
   inject API.
2. Implement `net_ebpf_ext_pend_operation()` as an extension helper
   function. This handles WFP context extraction, value population,
   internal tracking state initialization, and map insertion in a
   single call.
3. Implement `net_ebpf_ext_complete_operation()` as an extension helper
   function. This internally calls `bpf_map_update_elem` (to store the
   verdict) then `bpf_map_delete_elem` (to trigger WFP completion via
   `process_map_delete_element`), routing through the same single
   completion path as the normal COMPLETE flow. Used by the eBPF
   program during CONTINUE re-invocation to finalize a connection
   with PERMIT/BLOCK.
4. Implement the custom map provider:
   - Extension-controlled value size: Append internal tracking fields
     (WFP layer ID, lifecycle flags) after the caller's value.
     Return only the caller-visible portion on lookups.
   - `process_map_create`: Validate key/value sizes meet minimum
     requirements.
   - `process_map_add_element` (verdict update): Validate action is
     `PERMIT`, `BLOCK`, or `CONTINUE`. For PERMIT/BLOCK, store the
     verdict. For CONTINUE, queue re-invocation work item. Return
     error if entry is already completed.
   - `process_map_delete_element` (COMPLETE path): Read stored verdict
     from action field (default to BLOCK if still PENDING), verify not
     already completed. For **CONNECT**: store verdict in the
     per-processor pending completion context, call
     `FwpsCompleteOperation(ctx, NULL)` -- reauth fires inline, the
     classifyFn reads the verdict from the per-processor slot. If
     PERMIT, queue a threaded DPC to reinject the cloned NBL via
     `FwpsInjectTransportSendAsync`. If BLOCK, free the cloned NBL.
     For **RECV_ACCEPT**: call
     `FwpsCompleteOperation(ctx, NULL)`. If PERMIT, queue a threaded
     DPC to reinject the cloned NBL via
     `FwpsInjectTransportReceiveAsync`. If BLOCK, free the cloned
     NBL. Remove the map entry after completion.
   - `process_map_delete` (map destruction): In normal operation the
     management process drains all entries before unload. Defensively
     call `FwpsCompleteOperation(ctx, NULL)` for remaining entries
     (BLOCK -- CONNECT via synchronous reauth then free cloned NBL,
     RECV_ACCEPT then free cloned NBL) and log a warning.
5. Handle the `BPF_SOCK_ADDR_VERDICT_PEND` return value in the
   classify callback: call `FwpsPendOperation()` using the
   `completionHandle` from classify metadata, store the returned
   `completionContext`, cloned NBL, and reinject parameters
   (endpoint handle, addresses, interface indexes, etc.) in the
   entry's internal tracking state, then set `FWP_ACTION_BLOCK` with
   `FWPS_CLASSIFY_OUT_FLAG_ABSORB` and return to WFP. If
   `FwpsPendOperation()` fails, remove the map entry and return BLOCK.
6. Handle non-PEND verdict after `pend()`: when the program returns a
   non-PEND verdict after `net_ebpf_ext_pend_operation()` was called,
   automatically remove the orphaned map entry (no WFP calls needed
   since the operation was never pended).
7. Register the custom map provider as an NMR provider for the Map
   Information NPI.
8. Implement CONTINUE support: save eBPF program context at pend time,
   implement worker thread re-invocation of the eBPF program using
   saved context, handle re-PEND (skip `FwpsPendOperation()` when
   `lifecycle_state` is already `PENDED` -- cannot re-pend during
   reauth).
9. Handle PEND in multi-program chains: treat PEND as an early exit
   (stop invoking subsequent programs), save the aggregate verdict
   from prior programs in the pend map entry's internal tracking
   state, and combine it with the final verdict on COMPLETE using
   the existing max-priority logic.
10. Create an injection handle (`FwpsInjectionHandleCreate`) at driver
    initialization for use by `FwpsInjectTransportSendAsync` (CONNECT)
    and `FwpsInjectTransportReceiveAsync` (RECV_ACCEPT). Destroy
    it at driver unload.
11. Implement CONNECT PERMIT reinject path: after reauth permits,
    queue a threaded DPC that calls `FwpsInjectTransportSendAsync` with
    the cloned NBL. Free the cloned NBL in the injection completion
    callback. For CONNECT BLOCK, free the cloned NBL after
    `FwpsCompleteOperation()` returns.
12. Implement RECV_ACCEPT PERMIT reinject path: after
    `FwpsCompleteOperation(ctx, NULL)`, queue a threaded DPC that calls
    `FwpsInjectTransportReceiveAsync` with the cloned NBL. Free the
    cloned NBL in the injection completion callback. For RECV_ACCEPT
    BLOCK, free the cloned NBL after `FwpsCompleteOperation()` returns.
13. Implement self-injection check: at the top of the classifyFn, call
    `FwpsQueryPacketInjectionState` and permit immediately for
    `FWPS_PACKET_INJECTED_BY_SELF` /
    `FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF` to avoid re-inspecting
    reinjected packets.

Notes:
1. This proposal outlines a generic pend/complete feature that
   netebpfext can implement and any consumer can use.
2. ebpf-for-windows generally aligns with Linux features where they
   exist. Pend/complete is a Windows/WFP-specific concept with no Linux
   analogy.
3. BPF programs have a limited stack size (512 bytes). Programs may
   need to use a per-CPU array map (`BPF_MAP_TYPE_PERCPU_ARRAY` with a
   single entry, key=0) as scratch space for large temporary structs,
   rather than allocating them on the stack.
