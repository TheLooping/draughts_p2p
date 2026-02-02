#include "view.hpp"
#include <algorithm>

bool Views::active_contains(const std::string& peer_id) const {
    return active_.find(peer_id) != active_.end();
}

std::vector<proto::PeerDescriptor> Views::active_descriptors() const {
    std::vector<proto::PeerDescriptor> out;
    out.reserve(active_.size());
    for (const auto& kv : active_) out.push_back(kv.second.desc);
    return out;
}

void Views::upsert_active(const proto::PeerDescriptor& d, uint64_t now_ms) {
    ActiveEntry e;
    e.desc = d;
    e.last_seen_ms = now_ms;
    active_[d.peer_id] = std::move(e);

    // When someone becomes active, we can keep it out of passive to reduce duplicates
    if (passive_index_.count(d.peer_id)) {
        // lazy remove: rebuild if needed; for template we keep it simple
    }
}

void Views::touch_active(const std::string& peer_id, uint64_t now_ms) {
    auto it = active_.find(peer_id);
    if (it == active_.end()) return;
    it->second.last_seen_ms = now_ms;
}

void Views::remove_active(const std::string& peer_id) {
    active_.erase(peer_id);
}

std::optional<proto::PeerDescriptor> Views::get_active(const std::string& peer_id) const {
    auto it = active_.find(peer_id);
    if (it == active_.end()) return std::nullopt;
    return it->second.desc;
}

void Views::insert_passive(const proto::PeerDescriptor& d) {
    if (d.peer_id.empty()) return;
    if (active_.count(d.peer_id)) return;

    if (!passive_index_.count(d.peer_id)) {
        PassiveEntry e;
        e.desc = d;
        e.last_seen_ms = now_ms();
        e.age = 0;
        passive_.push_back(std::move(e));
        passive_index_.insert(d.peer_id);
    } else {
        // refresh last_seen if exists
        for (auto& e : passive_) {
            if (e.desc.peer_id == d.peer_id) {
                e.desc = d;
                e.last_seen_ms = now_ms();
                e.age = 0;
                break;
            }
        }
    }

    // enforce cap: evict oldest/last elements (simple)
    while (passive_.size() > passive_max_) {
        auto& front = passive_.front();
        passive_index_.erase(front.desc.peer_id);
        passive_.pop_front();
    }
}

std::optional<proto::PeerDescriptor> Views::pick_passive_random() {
    if (passive_.empty()) return std::nullopt;
    std::uniform_int_distribution<size_t> dist(0, passive_.size()-1);
    size_t idx = dist(rng_);
    auto d = passive_[idx].desc;
    // increase age of selected and others
    for (auto& e : passive_) e.age++;
    passive_[idx].age = 0;
    passive_[idx].last_seen_ms = now_ms();
    return d;
}

std::vector<proto::PeerDescriptor> Views::sample_for_shuffle(size_t k) const {
    std::vector<proto::PeerDescriptor> pool;
    pool.reserve(passive_.size() + active_.size());
    for (const auto& e : passive_) pool.push_back(e.desc);
    for (const auto& kv : active_) pool.push_back(kv.second.desc);

    if (pool.empty()) return {};
    std::vector<proto::PeerDescriptor> out;
    out.reserve(std::min(k, pool.size()));

    // random sample without replacement (simple shuffle)
    auto tmp = pool;
    std::shuffle(tmp.begin(), tmp.end(), rng_);
    for (size_t i = 0; i < std::min(k, tmp.size()); ++i) out.push_back(tmp[i]);
    return out;
}

void Views::merge_shuffle_sample(const std::vector<proto::PeerDescriptor>& sample) {
    for (const auto& d : sample) insert_passive(d);
}

std::vector<proto::PeerDescriptor> Views::expire_active(uint64_t now, uint64_t timeout_ms) {
    std::vector<proto::PeerDescriptor> removed;
    std::vector<std::string> to_remove;
    for (const auto& kv : active_) {
        if (now - kv.second.last_seen_ms > timeout_ms) {
            to_remove.push_back(kv.first);
            removed.push_back(kv.second.desc);
        }
    }
    for (const auto& id : to_remove) active_.erase(id);
    return removed;
}

std::optional<proto::PeerDescriptor> Views::evict_active_random() {
    if (active_.empty()) return std::nullopt;
    std::uniform_int_distribution<size_t> dist(0, active_.size()-1);
    size_t idx = dist(rng_);
    auto it = active_.begin();
    std::advance(it, idx);
    auto desc = it->second.desc;
    active_.erase(it);
    return desc;
}
