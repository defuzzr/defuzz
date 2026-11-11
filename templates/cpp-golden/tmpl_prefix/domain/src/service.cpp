#include "domain/service.hpp"

#include <string>

namespace fd = ws_tmpl_prefix::foundation;

namespace ws_tmpl_prefix::domain {

auto workspace_name() noexcept -> std::string_view {
    return fd::workspace_name();
}

auto format_banner(std::string_view label) -> std::string {
    std::string out{fd::workspace_name()};
    if (!label.empty()) {
        out.append(":");
        out.append(label);
    }
    return out;
}

} // namespace ws_tmpl_prefix::domain
