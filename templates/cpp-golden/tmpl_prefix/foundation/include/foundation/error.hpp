#pragma once

#include <string>
#include <string_view>

namespace ws_tmpl_prefix::foundation {

inline constexpr std::string_view kWorkspaceName =
    // Canonical kebab-case workspace slug.
    "tmpl-prefix";

inline constexpr std::string_view kWorkspaceSnake =
    // Canonical snake_case workspace identifier.
    "tmpl_prefix";

inline constexpr std::string_view kEnvPrefix =
    // Canonical SCREAMING_SNAKE_CASE environment prefix.
    "TMPL_PREFIX";

struct TmplPrefixInfo {
    std::string_view name{kWorkspaceName};
    std::string_view snake{kWorkspaceSnake};
    std::string_view env_prefix{kEnvPrefix};
};

using WorkspaceInfo = TmplPrefixInfo;

class Error {
  public:
    explicit Error(std::string message);

    [[nodiscard]] auto message() const noexcept -> std::string_view;

  private:
    std::string message_;
};

[[nodiscard]] auto workspace_info() noexcept -> WorkspaceInfo;
[[nodiscard]] auto workspace_name() noexcept -> std::string_view;

} // namespace ws_tmpl_prefix::foundation
