#include "adapters/memory_repo.hpp"
#include "domain/service.hpp"
#include "foundation/error.hpp"

#include <string>

namespace fd = ws_tmpl_prefix::foundation;
namespace dm = ws_tmpl_prefix::domain;
namespace ad = ws_tmpl_prefix::adapters;

auto main() -> int {
    const fd::WorkspaceInfo info = fd::workspace_info();
    if (info.name != fd::kWorkspaceName || info.snake != fd::kWorkspaceSnake ||
        info.env_prefix != fd::kEnvPrefix) {
        return 1;
    }

    const fd::Error err{"sample failure"};
    if (err.message() != "sample failure") {
        return 1;
    }

    if (dm::workspace_name() != info.name ||
        dm::format_banner("ok") != std::string{info.name} + ":ok") {
        return 1;
    }

    ad::MemoryRepo repo;
    repo.put("alpha", "one");
    repo.put("alpha", "two");
    const auto found = repo.get("alpha");
    if (repo.size() != 1U || !found.has_value() || *found != "two" ||
        repo.get("missing").has_value() || ad::workspace_name() != info.name) {
        return 1;
    }
    return 0;
}
