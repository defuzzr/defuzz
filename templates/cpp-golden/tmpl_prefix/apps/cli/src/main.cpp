#include "adapters/memory_repo.hpp"
#include "domain/service.hpp"
#include "foundation/error.hpp"

#include <cstdio>
#include <string>

namespace fd = ws_tmpl_prefix::foundation;
namespace dm = ws_tmpl_prefix::domain;
namespace ad = ws_tmpl_prefix::adapters;

auto main() -> int {
    const auto info = fd::workspace_info();
    ad::MemoryRepo repo;
    repo.put("workspace", std::string{ad::workspace_name()});
    const auto banner = dm::format_banner("ready");
    if (info.name.empty() || banner.empty() || repo.size() != 1U) {
        return 1;
    }
    std::puts(std::string{info.name}.c_str());
    return 0;
}
