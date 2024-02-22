#include "siggy.h"

const std::vector<void*> Sgy::IScanEx(
    const std::vector<std::int16_t>& Pattern,
    const void* Min,
    const void* Max,
    std::size_t Limit,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::IScanEx(Pattern, Min, Max, Limit, Protection);
    return _Result ? _Result.value() : std::vector<void*>();
}

const std::vector<void*> Sgy::IScanModule(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit
) {
    auto _Result = Sgy::Err::IScanModule(Module, Pattern, Limit);
    return _Result ? _Result.value() : std::vector<void*>();
}

const std::vector<void*> Sgy::IScan(
    const std::vector<std::int16_t>& Pattern,
    std::size_t Limit,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::IScan(Pattern, Limit, Protection);
    return _Result ? _Result.value() : std::vector<void*>();
}

void* Sgy::IScanModuleF(
    const std::string_view Module,
    const std::vector<std::int16_t>& Pattern
) {
    auto _Result = Sgy::Err::IScanModuleF(Module, Pattern);
    return _Result ? _Result.value() : nullptr;
}

void* Sgy::IScanF(
    const std::vector<std::int16_t>& Pattern,
    std::uint32_t Protection
) {
    auto _Result = Sgy::Err::IScanF(Pattern, Protection);
    return _Result ? _Result.value() : nullptr;
}