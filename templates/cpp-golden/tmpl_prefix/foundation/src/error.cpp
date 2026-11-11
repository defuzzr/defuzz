#include "foundation/error.hpp"

#include <utility>

namespace ws_tmpl_prefix::foundation {

Error::Error(std::string message) : message_(std::move(message)) {}

auto Error::message() const noexcept -> std::string_view {
    return message_;
}

auto workspace_info() noexcept -> WorkspaceInfo {
    return WorkspaceInfo{};
}

auto workspace_name() noexcept -> std::string_view {
    return kWorkspaceName;
}

} // namespace ws_tmpl_prefix::foundation
