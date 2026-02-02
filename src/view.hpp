#pragma once
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <random>
#include <optional>
#include "protocol.hpp"
#include "util.hpp"

struct ActiveEntry {
    proto::PeerDescriptor desc;
    uint64_t last_seen_ms = 0;
};

struct PassiveEntry {
    proto::PeerDescriptor desc;
    uint64_t last_seen_ms = 0;
    uint64_t age = 0;
};

class Views {
public:
    Views(size_t passive_max, size_t active_max)
        : passive_max_(passive_max), active_max_(active_max) {}

    // Active
    bool active_contains(const std::string& peer_id) const;
    size_t active_size() const { return active_.size(); }
    std::vector<proto::PeerDescriptor> active_descriptors() const;

    void upsert_active(const proto::PeerDescriptor& d, uint64_t now_ms);
    void touch_active(const std::string& peer_id, uint64_t now_ms);
    void remove_active(const std::string& peer_id);
    std::optional<proto::PeerDescriptor> get_active(const std::string& peer_id) const;

    // Passive
    size_t passive_size() const { return passive_.size(); }
    void insert_passive(const proto::PeerDescriptor& d);
    std::optional<proto::PeerDescriptor> pick_passive_random();
    std::vector<proto::PeerDescriptor> sample_for_shuffle(size_t k) const;
    void merge_shuffle_sample(const std::vector<proto::PeerDescriptor>& sample);

    // Maintenance
    std::vector<proto::PeerDescriptor> expire_active(uint64_t now_ms, uint64_t timeout_ms);
    std::optional<proto::PeerDescriptor> evict_active_random();

private:
    size_t passive_max_;
    size_t active_max_;

    std::unordered_map<std::string, ActiveEntry> active_;
    std::deque<PassiveEntry> passive_; // small template; replace with better structure if needed
    std::unordered_set<std::string> passive_index_;

    mutable std::mt19937 rng_{std::random_device{}()};
};
