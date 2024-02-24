/*
 *  Copyright (c) 2024 Creaffy.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once
#include <vector>
#include <string>
#include <expected>
#include <windows.h>
#include "pattern.h"

namespace sgy {
    constexpr inline std::size_t NO_LIMIT = 0;
    constexpr inline std::uint32_t PAGE_ANY_READABLE = (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY);

    enum ERROR_CODE : std::uint8_t {
        // Function succeeded but no results were found
        ERROR_NO_RESULTS,
        // Module with the provided name is not presnt in the process
        ERROR_BAD_MODULE,
        // Pattern contains integers smaller than -1 or greater than 255
        ERROR_BAD_PATTERN,
        // Provided page protection filter is not readable
        ERROR_BAD_PROTECTION,
        // Provided process handle is either not valid or doesn't have required priviliges
        ERROR_BAD_PROCESS,
        // Minimal address was greater or equal to Maximal
        ERROR_BAD_RANGE,
        // VirtualQuery or VirtualQueryEx call failed
        ERROR_VQUERY_FAILED,
        // ReadProcessMemory call failed
        ERROR_RPM_FAILED,
        // CreateToolhelp32Snapshot or Module32First call failed
        ERROR_SNAPSHOT_FAILED,
        // Something is deeply wrong
        ERROR_UNKNOWN = 0xFF
    };

    const std::string_view stringify_error(
        ERROR_CODE Error
    );

    // Internal Scanner
    namespace in {
        std::expected<const std::vector<void*>, ERROR_CODE> scan_ex(
            const std::vector<std::int16_t>& Pattern,
            const void* Min,
            const void* Max,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<const std::vector<void*>, ERROR_CODE> scan_module(
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT
        );

        std::expected<const std::vector<void*>, ERROR_CODE> scan(
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<void*, ERROR_CODE> scan_module_first(
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern
        );

        std::expected<void*, ERROR_CODE> scan_first(
            const std::vector<std::int16_t>& Pattern,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );
    }

    // External Scanner
    namespace ex {
        std::expected<const std::vector<void*>, ERROR_CODE> scan_ex(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            const void* Min,
            const void* Max,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<const std::vector<void*>, ERROR_CODE> scan_module(
            HANDLE Process,
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT
        );

        std::expected<const std::vector<void*>, ERROR_CODE> scan(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<void*, ERROR_CODE> scan_module_first(
            HANDLE Process,
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern
        );

        std::expected<void*, ERROR_CODE> scan_first(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );
    }
}