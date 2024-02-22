#include "siggy.h"

const std::vector<void*> Sgy::EScanEx(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    const void* Min,
    const void* Max,
    std::size_t Limit,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::EScanEx(Process, Pattern, Min, Max, Limit, Protection);
    return _Result ? _Result.value() : std::vector<void*>();
}

const std::vector<void*> Sgy::EScanModule(
    HANDLE Process,
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    auto _Result = Sgy::Err::EScanModule(Process, Module, Pattern, Limit);
    return _Result ? _Result.value() : std::vector<void*>();
}

const std::vector<void*> Sgy::EScanModule(
    HANDLE Process,
    const std::wstring_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    auto _Result = Sgy::Err::EScanModule(Process, Module, Pattern, Limit);
    return _Result ? _Result.value() : std::vector<void*>();
}

const std::vector<void*> Sgy::EScan(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::EScan(Process, Pattern, Limit, Protection);
    return _Result ? _Result.value() : std::vector<void*>();
}

void* Sgy::EScanModuleF(
    HANDLE Process,
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = Sgy::Err::EScanModuleF(Process, Module, Pattern);
    return _Result ? _Result.value() : nullptr;
}

void* EScanModuleF(
    HANDLE Process,
    const std::wstring_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = Sgy::Err::EScanModuleF(Process, Module, Pattern);
    return _Result ? _Result.value() : nullptr;
}

void* Sgy::EScanF(
    HANDLE Process,
    const std::vector<std::int16_t>& Pattern,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::EScanF(Process, Pattern, Protection);
    return _Result ? _Result.value() : nullptr;
}