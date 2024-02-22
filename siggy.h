#pragma once
#include <vector>
#include <string>
#include <expected>
#include <windows.h>
#include "pattern.h"

/*
* ======================== COUPLE IMPORTANT NOTES ABOUT SIGGY ========================
* 
* - PAGE_ANY_READABLE means that every readable page will be scanned, so:
*   PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY,
*   PAGE_READWRITE, PAGE_WRITECOPY.
* 
* - Scan range is always [Min, Max].
* 
* - The Sgy::Pat namespace contains helper functions for generating patterns.
* 
* - The Sgy::Err namespace contains functions that return an error code if something
*   goes wrong, the normal ones still use Sgy::Err functions under the hood.
* 
* - If a function succeeds but doesn't find any memory matching the pattern,
*   the expected type will be returned but the size will be 0 (std::vector<void*>)
*   or the pointer value will equal 0 (void*).
* 
* ====================================================================================
*/

namespace Sgy {
    constexpr inline std::size_t NO_LIMIT = 0;
    constexpr inline std::uint32_t PAGE_ANY_READABLE = 0;

    const std::vector<void*> IScanEx(
        const std::vector<std::int16_t>& Pattern,
        const void* Min,
        const void* Max,
        std::size_t Limit = NO_LIMIT,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    const std::vector<void*> IScanModule(
        const std::string_view Module,
        const std::vector<std::int16_t>& Pattern,
        std::size_t Limit = NO_LIMIT
    );

    const std::vector<void*> IScan(
        const std::vector<std::int16_t>& Pattern,
        std::size_t Limit = NO_LIMIT,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    void* IScanModuleF(
        const std::string_view Module,
        const std::vector<std::int16_t>& Pattern
    );

    void* IScanF(
        const std::vector<std::int16_t>& Pattern,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    const std::vector<void*> EScanEx(
        HANDLE Process,
        const std::vector<std::int16_t>& Pattern,
        const void* Min,
        const void* Max,
        std::size_t Limit = NO_LIMIT,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    const std::vector<void*> EScanModule(
        HANDLE Process,
        const std::string_view Module,
        const std::vector<std::int16_t>& Pattern,
        std::size_t Limit = NO_LIMIT
    );

    const std::vector<void*> EScanModule(
        HANDLE Process,
        const std::wstring_view Module,
        const std::vector<std::int16_t>& Pattern,
        std::size_t Limit = NO_LIMIT
    );

    const std::vector<void*> EScan(
        HANDLE Process,
        const std::vector<std::int16_t>& Pattern,
        std::size_t Limit = NO_LIMIT,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    void* EScanF(
        HANDLE Process,
        const std::vector<std::int16_t>& Pattern,
        std::uint32_t Protection = PAGE_ANY_READABLE
    );

    void* EScanModuleF(
        HANDLE Process,
        const std::string_view Module,
        const std::vector<std::int16_t>& Pattern
    );

    void* EScanModuleF(
        HANDLE Process,
        const std::wstring_view Module,
        const std::vector<std::int16_t>& Pattern
    );

    namespace Err {
        enum ERROR_CODE : std::uint8_t {
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
            ERROR_SNAPSHOT_FAILED
        };

        const std::string_view Stringify(
            ERROR_CODE Error
        );

        std::expected<const std::vector<void*>, ERROR_CODE> IScanEx(
            const std::vector<std::int16_t>& Pattern,
            const void* Min,
            const void* Max,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<const std::vector<void*>, ERROR_CODE> IScanModule(
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT
        );

        std::expected<const std::vector<void*>, ERROR_CODE> IScan(
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<void*, ERROR_CODE> IScanModuleF(
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern
        );

        std::expected<void*, ERROR_CODE> IScanF(
            const std::vector<std::int16_t>& Pattern,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<const std::vector<void*>, ERROR_CODE> EScanEx(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            const void* Min,
            const void* Max,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<const std::vector<void*>, ERROR_CODE> EScanModule(
            HANDLE Process,
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT
        );

        std::expected<const std::vector<void*>, ERROR_CODE> EScanModule(
            HANDLE Process,
            const std::wstring_view Module,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT
        );

        std::expected<const std::vector<void*>, ERROR_CODE> EScan(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            std::size_t Limit = NO_LIMIT,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<void*, ERROR_CODE> EScanF(
            HANDLE Process,
            const std::vector<std::int16_t>& Pattern,
            std::uint32_t Protection = PAGE_ANY_READABLE
        );

        std::expected<void*, ERROR_CODE> EScanModuleF(
            HANDLE Process,
            const std::string_view Module,
            const std::vector<std::int16_t>& Pattern
        );

        std::expected<void*, ERROR_CODE> EScanModuleF(
            HANDLE Process,
            const std::wstring_view Module,
            const std::vector<std::int16_t>& Pattern
        );
    }
}