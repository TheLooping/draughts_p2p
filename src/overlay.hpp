#pragma once

#include <boost/asio.hpp>

#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "config.hpp"
#include "io_layer.hpp"
#include "logger.hpp"
#include "protocol.hpp"
#include "view.hpp"

class HyparviewOverlay {
public:
    struct TwoHopNeighbor {
        proto::PeerDescriptor desc;
        uint64_t expires_at_ms = 0;
    };

    struct TwoHopEntry {
        std::string via_peer_id;
        std::vector<TwoHopNeighbor> neighbors;
        uint64_t expires_at_ms = 0;
        uint32_t stale_rounds = 0;
    };

    struct Status {
        proto::PeerDescriptor self;
        size_t active = 0;
        size_t passive = 0;
        size_t directory = 0;
    };

    HyparviewOverlay(IoLayer& io,
                     Config cfg,
                     proto::PeerDescriptor self,
                     Logger& logger);

    bool start();
    void stop();

    void on_datagram(const tlv::Bytes& bytes, const boost::asio::ip::udp::endpoint& from);

    Status status() const;
    proto::PeerDescriptor self_descriptor() const;
    std::vector<proto::PeerDescriptor> active_neighbors() const;
    std::vector<TwoHopEntry> twohop_snapshot() const;
    std::vector<proto::PeerDescriptor> directory_snapshot(size_t limit = 0) const;
    size_t directory_size() const;

    std::optional<proto::PeerDescriptor> lookup_peer(const std::string& peer_id) const;
    std::optional<proto::PeerDescriptor> lookup_peer_by_draughts_endpoint(const boost::asio::ip::address_v4& addr,
                                                                          uint16_t port) const;
    std::optional<proto::PeerDescriptor> pick_random_active_except(const std::string& exclude_peer_id) const;
    std::optional<std::string> pick_nnh_for(const std::string& nh_peer_id,
                                            const std::string& exclude_peer_id) const;

private:
    using udp = boost::asio::ip::udp;

    void handle_join(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_forward_join(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_join_accept(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_ping(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_pong(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_view_update(const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_view_update_req(const tlv::Bytes& payload, const udp::endpoint& from);

    void tick_ping();
    void tick_neighbor_check();
    void tick_view_update();
    void tick_directory_scan();

    void ensure_active_in_range();
    void accept_joiner(const proto::PeerDescriptor& d, const udp::endpoint& from);
    void forward_join(const proto::PeerDescriptor& d, uint16_t ttl, const std::string& from_peer);
    void send_join(const proto::PeerDescriptor& target);
    void send_view_update_to(const proto::PeerDescriptor& target);
    void send_view_update_req(const proto::PeerDescriptor& target);
    void send_ping_to(const proto::PeerDescriptor& target);

    void learn_peer(const proto::PeerDescriptor& d, const udp::endpoint* from);
    void expire_directory(uint64_t now_ms);
    void expire_twohop(uint64_t now_ms);

    std::optional<std::string> peer_id_from_endpoint(const udp::endpoint& ep) const;
    std::optional<udp::endpoint> overlay_endpoint_for(const proto::PeerDescriptor& d) const;

    void update_active_neighbors_file(bool force);
    void remove_active_neighbors_file();
    void write_self_info_file();
    void remove_self_info_file();

private:
    struct DirectoryRec {
        proto::PeerDescriptor desc;
        uint64_t expires_at_ms = 0;
        uint32_t stale_rounds = 0;
    };

    struct TwoHopRec {
        std::vector<TwoHopNeighbor> neighbors;
        uint64_t expires_at_ms = 0;
        uint32_t stale_rounds = 0;
    };

    IoLayer& io_;
    Config cfg_;
    proto::PeerDescriptor self_;
    Logger& logger_;

    Views views_;

    std::unordered_map<std::string, DirectoryRec> directory_;
    std::unordered_map<std::string, std::string> overlay_addr_to_peer_id_;
    std::unordered_map<std::string, std::string> draughts_addr_to_peer_id_;

    std::unordered_map<std::string, TwoHopRec> twohop_;

    boost::asio::steady_timer t_ping_;
    boost::asio::steady_timer t_neighbor_check_;
    boost::asio::steady_timer t_view_update_;
    boost::asio::steady_timer t_directory_;

    mutable std::mt19937 rng_{std::random_device{}()};

    std::string neighbors_snapshot_;
    std::unordered_set<std::string> active_neighbor_set_;
};
