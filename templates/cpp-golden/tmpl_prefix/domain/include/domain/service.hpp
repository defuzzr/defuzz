#pragma once

#include "foundation/error.hpp"

#include <string>
#include <string_view>

namespace ws_tmpl_prefix::domain {

struct Item {
    std::string key;
    std::string value;
};

[[nodiscard]] auto workspace_name() noexcept -> std::string_view;
[[nodiscard]] auto format_banner(std::string_view label) -> std::string;

} // namespace ws_tmpl_prefix::domain
