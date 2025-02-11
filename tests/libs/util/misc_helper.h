// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @brief Miscellaneous test helper functions.
 */

#pragma once
#include <atomic>

/**
 * @brief Helper function to get a 64-bit number where high-order 32 bits contain the process ID and
 * the remaining 32 bits contains the thread ID.
 */
uint64_t
get_current_pid_tgid();

thread_local bool _is_main_thread = false;

struct test_failure : std::exception
{
    test_failure(const std::string& message) : message(message) {}
    std::string message;
};

#define SAFE_REQUIRE(x)                                               \
    if (_is_main_thread) {                                            \
        REQUIRE(x);                                                   \
    } else {                                                          \
        if (!(x)) {                                                   \
            throw test_failure("Condition failed" + std::string(#x)); \
        }                                                             \
    }