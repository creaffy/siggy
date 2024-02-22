#include "siggy.h"
#include <psapi.h>

const std::string_view sgy::stringify_error(
    sgy::ERROR_CODE Error
) {
    switch (Error) {
    case ERROR_BAD_MODULE: return "ERROR_BAD_MODULE";
    case ERROR_BAD_PATTERN: return "ERROR_BAD_PATTERN";
    case ERROR_BAD_PROTECTION: return "ERROR_BAD_PROTECTION";
    case ERROR_BAD_PROCESS: return "ERROR_BAD_PROCESS";
    case ERROR_BAD_RANGE: return "ERROR_BAD_RANGE";
    case ERROR_VQUERY_FAILED: return "ERROR_VQUERY_FAILED";
    case ERROR_RPM_FAILED: return "ERROR_RPM_FAILED";
    case ERROR_SNAPSHOT_FAILED: return "ERROR_SNAPSHOT_FAILED";
    case ERROR_NO_RESULTS: return "ERROR_NO_RESULTS";
    default: return "ERROR_UNKNOWN";
    }
}

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::in::scan_ex(
    const std::vector<std::int16_t>& Pattern,
    const void* Min,
    const void* Max,
    std::size_t Limit,
    std::uint32_t Protection
) {
    for (const std::int16_t& e : Pattern) {
        if ((e < -1) || (e > 255))
            return std::unexpected(ERROR_BAD_PATTERN);
    }

    if ((Protection & PAGE_ANY_READABLE) == 0)
        return std::unexpected(ERROR_BAD_PROTECTION);

    std::vector<void*> _Results;
    const std::uintptr_t _Min = reinterpret_cast<std::uintptr_t>(Min);
    const std::uintptr_t _Max = reinterpret_cast<std::uintptr_t>(Max);

    if (_Min > _Max)
        return std::unexpected(ERROR_BAD_RANGE);

    std::vector<MEMORY_BASIC_INFORMATION> _Regions;
    MEMORY_BASIC_INFORMATION _MemoryInfo{};
    for (auto i = _Min; i <= _Max; i++) {
        if (!VirtualQuery(reinterpret_cast<void*>(i), &_MemoryInfo, sizeof(_MemoryInfo)))
            return std::unexpected(ERROR_VQUERY_FAILED);
        _Regions.push_back(_MemoryInfo);
        i += _MemoryInfo.RegionSize;
    }

    for (auto& _Region : _Regions) {
        if (((_Region.State & (MEM_COMMIT | MEM_RESERVE)) == 0) || ((_Region.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_TARGETS_INVALID)) != 0) ||
            (_Region.Protect == 0) || ((_Region.Protect & Protection) == 0))
            continue;

        for (std::uintptr_t i = 0; i < _Region.RegionSize - Pattern.size(); i++) {
            if (reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i < _Min)
                continue;
            if (reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i > _Max)
                goto exit;

            bool _Found = true;
            for (std::size_t j = 0; j < Pattern.size(); j++) {
                if ((Pattern[j] == -1) || (*reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i + j) == Pattern[j]))
                    continue;
                _Found = false;
                break;
            }
            if (_Found) {
                _Results.push_back(reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i));
                if ((Limit != NO_LIMIT) && (_Results.size() == Limit))
                    return _Results;
            }
        }
    }

exit:
    if (_Results.empty())
        return std::unexpected(ERROR_NO_RESULTS);
    else
        return _Results;
}

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::in::scan_module(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    HMODULE _Module = GetModuleHandleA(Module.data());
    if (!_Module)
        return std::unexpected(ERROR_BAD_MODULE);
    MODULEINFO _ModuleInfo{};
    if (!K32GetModuleInformation(GetCurrentProcess(), _Module, &_ModuleInfo, sizeof(_ModuleInfo)))
        return std::unexpected(ERROR_UNKNOWN);
    return scan_ex(Pattern, _Module, reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(_Module) + _ModuleInfo.SizeOfImage), Limit);
}

std::expected<const std::vector<void*>, sgy::ERROR_CODE> sgy::in::scan(
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit,
    std::uint32_t Protection
) {
    SYSTEM_INFO _SystemInfo{};
    GetSystemInfo(&_SystemInfo);
    return scan_ex(Pattern, _SystemInfo.lpMinimumApplicationAddress, _SystemInfo.lpMaximumApplicationAddress, Limit, Protection);
}

std::expected<void*, sgy::ERROR_CODE> sgy::in::scan_module_first(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = scan_module(Module, Pattern, 1);
    if (_Result) 
        return _Result->front();
    else 
        return std::unexpected(_Result.error());
}

std::expected<void*, sgy::ERROR_CODE> sgy::in::scan_first(
    const std::vector<std::int16_t>& Pattern,
    std::uint32_t Protection
) {
    auto _Result = scan(Pattern, 1, Protection);
    if (_Result)
        return _Result->front();
    else
        return std::unexpected(_Result.error());
}