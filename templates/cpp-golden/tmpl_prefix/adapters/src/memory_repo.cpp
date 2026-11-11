#include "adapters/memory_repo.hpp"

#include <utility>

namespace dm = ws_tmpl_prefix::domain;

namespace ws_tmpl_prefix::adapters {

void MemoryRepo::put(std::string key, std::string value) {
    for (auto& item : items_) {
        if (item.key == key) {
            item.value = std::move(value);
            return;
        }
    }
    items_.push_back(dm::Item{.key = std::move(key), .value = std::move(value)});
}

auto MemoryRepo::get(std::string_view key) const -> std::optional<std::string> {
    for (const auto& item : items_) {
        if (item.key == key) {
            return item.value;
        }
    }
    return std::nullopt;
}

auto MemoryRepo::size() const noexcept -> std::size_t {
    return items_.size();
}

auto workspace_name() noexcept -> std::string_view {
    return dm::workspace_name();
}

} // namespace ws_tmpl_prefix::adapters
