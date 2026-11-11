#pragma once

#include "domain/service.hpp"
#include "foundation/error.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ws_tmpl_prefix::adapters {

class MemoryRepo {
  public:
    void put(std::string key, std::string value);

    [[nodiscard]] auto get(std::string_view key) const -> std::optional<std::string>;
    [[nodiscard]] auto size() const noexcept -> std::size_t;

  private:
    std::vector<domain::Item> items_;
};

[[nodiscard]] auto workspace_name() noexcept -> std::string_view;

} // namespace ws_tmpl_prefix::adapters
