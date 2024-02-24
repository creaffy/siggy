#include "siggy.h"
#include <psapi.h>
#include <tlhelp32.h>

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::ex::scan_ex(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    const void* Min,
    const void* Max,
    std::size_t Limit,
    std::uint32_t Protection
) {
    if (!Process || (Process == INVALID_HANDLE_VALUE))
        return std::unexpected(ERROR_BAD_PROCESS);

    for (const std::int16_t& e : Pattern) {
        if ((e < -1) || (e > 255))
            return std::unexpected(ERROR_BAD_PATTERN);
    }
    
    if ((Protection & PAGE_ANY_READABLE) == 0)
        return std::unexpected(ERROR_BAD_PROTECTION);

    std::vector<void*> _Results;
    const std::uintptr_t _Min = reinterpret_cast<std::uintptr_t>(Min);
    const std::uintptr_t _Max = reinterpret_cast<std::uintptr_t>(Max);

    const std::size_t _InitialLimit = Limit;

    std::vector<MEMORY_BASIC_INFORMATION> _Regions;
    MEMORY_BASIC_INFORMATION _MemoryInfo{};
    for (auto i = _Min; i <= _Max; i++) {
        if (!VirtualQueryEx(Process, reinterpret_cast<void*>(i), &_MemoryInfo, sizeof(_MemoryInfo)))
            return std::unexpected(sgy::ERROR_VQUERY_FAILED);
        _Regions.push_back(_MemoryInfo);
        i += _MemoryInfo.RegionSize;
    }

    for (auto& _Region : _Regions) {
        if (((_Region.State & (MEM_COMMIT | MEM_RESERVE)) == 0) || ((_Region.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_TARGETS_INVALID)) != 0) ||
            (_Region.Protect == 0) || ((_Region.Protect & Protection) == 0))
            continue;

        std::vector<std::uint8_t> _Buffer;
        _Buffer.resize(_Region.RegionSize, 0);
        if (!ReadProcessMemory(Process, _Region.BaseAddress, _Buffer.data(), _Region.RegionSize, nullptr))
            return std::unexpected(ERROR_RPM_FAILED);

        auto _RegionResults = in::scan_ex(Pattern, &_Buffer.front(), &_Buffer.back(), Limit, Protection);
        if (!_RegionResults && _RegionResults.error() == ERROR_NO_RESULTS)
            continue;
        else if (!_RegionResults)
            return std::unexpected(_RegionResults.error());

        for (auto& i : _RegionResults.value()) {
            _Results.push_back(
                reinterpret_cast<void*>(
                    reinterpret_cast<std::uintptr_t>(i) - 
                    reinterpret_cast<std::uintptr_t>(_Buffer.data()) + 
                    reinterpret_cast<std::uintptr_t>(_Region.BaseAddress)));
        }

        if (_RegionResults->size() != Limit)
            Limit -= _RegionResults->size();

        if ((_InitialLimit != NO_LIMIT) && (Limit == 0))
            return _Results;
    }

    if (_Results.empty()) return std::unexpected(ERROR_NO_RESULTS);
    else return _Results;
}

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::ex::scan_module(
    HANDLE Process,
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    // I need to define this myself & use GetProcAddress for ansi Module32First and Module32Next because
    // tlhelp32.h overrides those with unicode versions using macros when your project is set to unicode
    struct MODULEENTRY32A {
        DWORD   dwSize;
        DWORD   th32ModuleID;
        DWORD   th32ProcessID;
        DWORD   GlblcntUsage;
        DWORD   ProccntUsage;
        BYTE*   modBaseAddr;
        DWORD   modBaseSize;
        HMODULE hModule;
        char    szModule[MAX_MODULE_NAME32 + 1];
        char    szExePath[MAX_PATH];
    };

    static HMODULE _Kernel32 = GetModuleHandleA("kernel32.dll");
    if (!_Kernel32)
        return std::unexpected(ERROR_UNKNOWN);
    static auto Module32FirstA = reinterpret_cast<BOOL(WINAPI*)(HANDLE, MODULEENTRY32A*)>(GetProcAddress(_Kernel32, "Module32First"));
    static auto Module32NextA = reinterpret_cast<BOOL(WINAPI*)(HANDLE, MODULEENTRY32A*)>(GetProcAddress(_Kernel32, "Module32Next"));

    auto _ToLower = [](const std::string_view _String) -> std::string {
        std::string _Result;
        for (auto& e : _String)
            _Result += std::tolower(e);
        return _Result;
    };

    HANDLE _Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(Process));
    if (!_Snapshot || (_Snapshot == INVALID_HANDLE_VALUE))
        return std::unexpected(ERROR_SNAPSHOT_FAILED);
    MODULEENTRY32A _Module{};
    _Module.dwSize = sizeof(_Module);
    if (!Module32FirstA(_Snapshot, &_Module)) {
        CloseHandle(_Snapshot);
        return std::unexpected(ERROR_SNAPSHOT_FAILED);
    }
    do {
        if (_ToLower(Module) == _ToLower(_Module.szModule)) {
            CloseHandle(_Snapshot);
            return scan_ex(Process, Pattern, _Module.modBaseAddr, _Module.modBaseAddr + _Module.modBaseSize - 1, Limit);
        }
    } while (Module32NextA(_Snapshot, &_Module));
    CloseHandle(_Snapshot);
    return std::unexpected(ERROR_BAD_MODULE);
}

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::ex::scan(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit,
    std::uint32_t Protection
) {
    SYSTEM_INFO _SystemInfo{};
    GetSystemInfo(&_SystemInfo);
    return scan_ex(Process, Pattern, _SystemInfo.lpMinimumApplicationAddress, _SystemInfo.lpMaximumApplicationAddress, Limit, Protection);
}

std::expected<void*, sgy::ERROR_CODE> sgy::ex::scan_module_first(
    HANDLE Process,
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = scan_module(Process, Module, Pattern, 1);
    if (_Result) return _Result->front();
    else return std::unexpected(_Result.error());
}

std::expected<void*, sgy::ERROR_CODE> sgy::ex::scan_first(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    std::uint32_t Protection
) {
    auto _Result = scan(Process, Pattern, 1, Protection);
    if (_Result) return _Result->front();
    else return std::unexpected(_Result.error());
}