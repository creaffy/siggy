#include "siggy.h"
#include <psapi.h>

static std::expected<const std::vector<MEMORY_BASIC_INFORMATION>, Sgy::Err::ERROR_CODE> _GetMemoryRegions(
    std::uintptr_t Min,
    std::uintptr_t Max
) {
    std::vector<MEMORY_BASIC_INFORMATION> _Regions;
    MEMORY_BASIC_INFORMATION _MemoryInfo{};
    for (auto i = Min; i <= Max; i++) {
        if (!VirtualQuery(reinterpret_cast<void*>(i), &_MemoryInfo, sizeof(_MemoryInfo)))
            return std::unexpected(Sgy::Err::ERROR_VQUERY_FAILED);
        _Regions.push_back(_MemoryInfo);
        i += _MemoryInfo.RegionSize;
    }
    return _Regions;
}

const std::string_view Sgy::Err::Stringify(
    Sgy::Err::ERROR_CODE Error
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
    default: return "ERROR_UNKNOWN";
    }
}

std::expected<const std::vector<void*>, Sgy::Err::ERROR_CODE> Sgy::Err::IScanEx(
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

    if ((Protection != PAGE_ANY_READABLE) &&
        (Protection != PAGE_EXECUTE_READ) &&
        (Protection != PAGE_EXECUTE_READWRITE) &&
        (Protection != PAGE_EXECUTE_WRITECOPY) &&
        (Protection != PAGE_READONLY) &&
        (Protection != PAGE_READWRITE) &&
        (Protection != PAGE_WRITECOPY))
        return std::unexpected(ERROR_BAD_PROTECTION);

    std::vector<void*> _Results;
    const std::uintptr_t _Min = reinterpret_cast<std::uintptr_t>(Min);
    const std::uintptr_t _Max = reinterpret_cast<std::uintptr_t>(Max);

    if (_Min > _Max)
        return std::unexpected(ERROR_BAD_RANGE);

    auto _Regions = _GetMemoryRegions(_Min, _Max);
    if (!_Regions)
        return std::unexpected(ERROR_VQUERY_FAILED);

    for (auto& _Region : _Regions.value()) {
        if (((_Region.State & (MEM_COMMIT | MEM_RESERVE)) == 0) ||
            ((_Region.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_TARGETS_INVALID)) != 0) ||
            (_Region.Protect == 0) ||
            ((Protection != Sgy::PAGE_ANY_READABLE) && (_Region.Protect != Protection)))
            continue;

        for (std::uintptr_t i = 0; i < _Region.RegionSize - Pattern.size(); i++) {
            if (reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i < _Min)
                continue;
            if (reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i > _Max)
                return _Results;

            bool _Found = true;
            for (std::size_t j = 0; j < Pattern.size(); j++) {
                if ((Pattern[j] == -1) || (*reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i + j) == Pattern[j]))
                    continue;
                _Found = false;
                break;
            }
            if (_Found) {
                _Results.push_back(reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(_Region.BaseAddress) + i));
                if (Limit != NO_LIMIT && _Results.size() == Limit)
                    return _Results;
            }
        }
    }

    return _Results;
}

std::expected<const std::vector<void*>, Sgy::Err::ERROR_CODE> Sgy::Err::IScanModule(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    HMODULE _Module = GetModuleHandleA(Module.data());
    if (!_Module)
        return std::unexpected(ERROR_BAD_MODULE);
    MODULEINFO _ModuleInfo{};
    if (!K32GetModuleInformation(GetCurrentProcess(), _Module, &_ModuleInfo, sizeof(_ModuleInfo)))
        return std::unexpected(ERROR_BAD_MODULE);
    return IScanEx(Pattern, _Module, reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(_Module) + _ModuleInfo.SizeOfImage), Limit);
}

std::expected<const std::vector<void*>, Sgy::Err::ERROR_CODE> Sgy::Err::IScan(
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit,
    std::uint32_t Protection
) {
    SYSTEM_INFO _SystemInfo{};
    GetSystemInfo(&_SystemInfo);
    return IScanEx(Pattern, _SystemInfo.lpMinimumApplicationAddress, _SystemInfo.lpMaximumApplicationAddress, Limit, Protection);
}

std::expected<void*, Sgy::Err::ERROR_CODE> Sgy::Err::IScanModuleF(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = IScanModule(Module, Pattern, 1);
    if (_Result) return _Result->empty() ? nullptr : _Result->front();
    else return std::unexpected(_Result.error());
}

std::expected<void*, Sgy::Err::ERROR_CODE> Sgy::Err::IScanF(
    const std::vector<std::int16_t>& Pattern,
    std::uint32_t Protection
) {
    auto _Result = IScan(Pattern, 1, Protection);
    if (_Result) return _Result->empty() ? nullptr : _Result->front();
    else return std::unexpected(_Result.error());
}