#pragma once
#include <vector>
#include <string>
#include <ranges>

namespace Sgy {
    namespace Pat {
        // Format: "55 56 48 83 EC ? 48 8D 6C 24 ? 48 89 CE E8"
        constexpr std::vector<std::int16_t> IDA(const std::string_view Pattern) {
            std::vector<std::int16_t> _Pattern;
            for (auto _Token : std::ranges::split_view(Pattern, ' '))
                _Pattern.push_back(std::string_view(_Token) == "?" ? -1 : std::stoi(_Token.data(), 0, 16));
            while (_Pattern.back() == -1)
                _Pattern.pop_back();
            return _Pattern;
        }

        // Format: "55 56 48 83 EC ?? 48 8D 6C 24 ?? 48 89 CE E8"
        constexpr std::vector<std::int16_t> X64DBG(const std::string_view Pattern) {
            std::vector<std::int16_t> _Pattern;
            for (auto _Token : std::ranges::split_view(Pattern, ' '))
                _Pattern.push_back(std::string_view(_Token) == "??" ? -1 : std::stoi(_Token.data(), 0, 16));
            while (_Pattern.back() == -1)
                _Pattern.pop_back();
            return _Pattern;
        }

        template <typename T>
        constexpr std::vector<std::int16_t> VALUE(const T& Value) {
            return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&Value), reinterpret_cast<const std::uint8_t*>(&Value) + sizeof(T));
        }

        constexpr std::vector<std::int16_t> STRING(const std::string_view String, bool NullTerminated = true) {
            return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&String.front()), reinterpret_cast<const std::uint8_t*>(&String.back()) + (NullTerminated ? 1 : 0));
        }

        constexpr std::vector<std::int16_t> WSTRING(const std::wstring_view String, bool NullTerminated = true) {
            return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&String.front()), reinterpret_cast<const std::uint8_t*>(&String.back()) + (NullTerminated ? 1 : 0));
        }
    }
}