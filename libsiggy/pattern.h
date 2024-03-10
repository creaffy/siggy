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
#include <ranges>

namespace sig::pat {
    // Format: "55 56 48 83 EC ? 48 8D 6C 24 ? 48 89 CE E8" (base 16)
    constexpr std::vector<std::int16_t> ida(const std::string_view Pattern, std::uint32_t Base = 16) {
        std::vector<std::int16_t> _Pattern;
        for (auto _Token : std::ranges::split_view(Pattern, ' '))
            _Pattern.push_back(std::string_view(_Token) == "?" ? -1 : std::stoi(_Token.data(), 0, Base));
        while (_Pattern.back() == -1)
            _Pattern.pop_back();
        return _Pattern;
    }

    // Format: "55 56 48 83 EC ?? 48 8D 6C 24 ?? 48 89 CE E8" (base 16)
    constexpr std::vector<std::int16_t> x64dbg(const std::string_view Pattern, std::uint32_t Base = 16) {
        std::vector<std::int16_t> _Pattern;
        for (auto _Token : std::ranges::split_view(Pattern, ' '))
            _Pattern.push_back(std::string_view(_Token) == "??" ? -1 : std::stoi(_Token.data(), 0, Base));
        while (_Pattern.back() == -1)
            _Pattern.pop_back();
        return _Pattern;
    }

    template <typename T>
    constexpr std::vector<std::int16_t> value(const T& Value) {
        return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&Value), reinterpret_cast<const std::uint8_t*>(&Value) + sizeof(T));
    }

    constexpr std::vector<std::int16_t> string(const std::string_view String, bool NullTerminated = true) {
        return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&String.front()), reinterpret_cast<const std::uint8_t*>(&String.back()) + (NullTerminated ? 1 : 0));
    }

    constexpr std::vector<std::int16_t> wstring(const std::wstring_view String, bool NullTerminated = true) {
        return std::vector<std::int16_t>(reinterpret_cast<const std::uint8_t*>(&String.front()), reinterpret_cast<const std::uint8_t*>(&String.back()) + (NullTerminated ? 1 : 0));
    }
}