#pragma once

#include <boost/asio.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <optional>
#include <random>

#include "config.hpp"
#include "console.hpp"
#include "logger.hpp"
#include "protocol.hpp"

class DraughtsNode {
public:
    DraughtsNode(boost::asio::io_context& io,
                 Config cfg,
                 proto::PeerDescriptor self,
                 Logger& logger,
                 Console& console);

    bool start();
    void stop();

    // CLI-driven actions (these should be called from io_context thread via post)
    void cmd_show_id();
    void cmd_show_neighbors();
    void cmd_show_twohop();
    void cmd_show_peers();

    // Overlay info for draughts app
    std::vector<proto::PeerDescriptor> all_peers() const;
    std::vector<proto::PeerDescriptor> active_neighbors() const;
    std::optional<proto::PeerDescriptor> lookup_peer(const std::string& peer_id) const;
    std::optional<proto::PeerDescriptor> lookup_peer_by_ipv4(const boost::asio::ip::address_v4& addr) const;
    std::optional<proto::PeerDescriptor> lookup_peer_by_draughts_endpoint(const boost::asio::ip::address_v4& addr,
                                                                          uint16_t port) const;
    std::optional<proto::PeerDescriptor> pick_random_active_except(const std::string& exclude_peer_id) const;
    std::optional<std::string> pick_nnh_for(const std::string& nh_peer_id,
                                           const std::string& exclude_peer_id) const;

private:
    struct TwoHopEntry {
        std::vector<proto::PeerDescriptor> neighbors;
    };

    // Timers
    void tick_housekeeping();
    void update_active_neighbors_file(bool force);
    void remove_active_neighbors_file();
    void write_self_info_file();
    void remove_self_info_file();
    bool load_static_topology();

    // Peer knowledge / lookup
    void learn_peer(const proto::PeerDescriptor& d);

private:
    boost::asio::io_context& io_;
    Config cfg_;
    proto::PeerDescriptor self_;

    Logger& logger_;
    Console& console_;

    // Active neighbors (static topology)
    std::vector<proto::PeerDescriptor> active_neighbors_;

    // Directories
    std::unordered_map<std::string, proto::PeerDescriptor> directory_;
    std::unordered_map<std::string, std::string> draughts_addr_to_peer_id_;

    // Two-hop cache (neighbor -> its active neighbors)
    std::unordered_map<std::string, TwoHopEntry> twohop_;

    // Timers
    boost::asio::steady_timer t_housekeeping_;

    // RNG
    mutable std::mt19937 rng_{std::random_device{}()};

    // Neighbor file tracking
    std::string neighbors_snapshot_;
    std::unordered_set<std::string> active_neighbor_set_;
};
