#pragma once

#include <boost/asio.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <optional>
#include <array>
#include <random>

#include "config.hpp"
#include "console.hpp"
#include "logger.hpp"
#include "protocol.hpp"
#include "view.hpp"

class DraughtsNode {
public:
    DraughtsNode(boost::asio::io_context& io,
                 Config cfg,
                 proto::PeerDescriptor self,
                 Logger& logger,
                 Console& console);

    void start();
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

    static std::string ep_to_string(const boost::asio::ip::udp::endpoint& ep);

private:
    using udp = boost::asio::ip::udp;

    struct Pending {
        proto::Message msg;
        udp::endpoint to;
        uint64_t created_ms = 0;
        uint64_t next_retry_ms = 0;
        int retries = 0;
        int max_retries = 3;
    };

    struct TwoHopEntry {
        std::vector<proto::PeerDescriptor> neighbors;
        uint64_t updated_ms = 0;
    };

    // Networking
    void do_receive();
    void on_datagram(const tlv::Bytes& bytes, const udp::endpoint& from);
    void send_msg(const proto::Message& m, const udp::endpoint& to);

    // Timers
    void tick_keepalive();
    void tick_shuffle();
    void tick_repair();
    void tick_pending();
    void tick_neighbor_set();
    void tick_housekeeping();
    void update_active_neighbors_file(bool force);
    void remove_active_neighbors_file();
    void write_self_info_file();
    void remove_self_info_file();

    // Overlay handlers
    void handle_join(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_forward_join(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_add_req(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_add_ack(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_keepalive(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_shuffle_req(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_shuffle_resp(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);
    void handle_neighbor_set(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from);

    // Overlay logic
    void ensure_active_in_range();
    void try_add_active(const proto::PeerDescriptor& d);
    std::vector<proto::PeerDescriptor> referrals(size_t n) const;

    // Peer knowledge / lookup
    void learn_peer(const proto::PeerDescriptor& d);
    std::optional<std::string> peer_id_from_endpoint(const udp::endpoint& ep) const;

private:
    boost::asio::io_context& io_;
    Config cfg_;
    proto::PeerDescriptor self_;

    Logger& logger_;
    Console& console_;

    // UDP
    udp::socket sock_;
    udp::endpoint remote_;
    std::array<uint8_t, 4096> rxbuf_{};

    // Views
    Views views_;

    // Directories
    std::unordered_map<std::string, proto::PeerDescriptor> directory_;
    std::unordered_map<std::string, std::string> addr_to_peer_id_;
    std::unordered_map<std::string, std::string> draughts_addr_to_peer_id_;

    // Two-hop cache (neighbor -> its active neighbors)
    std::unordered_map<std::string, TwoHopEntry> twohop_;

    // Pending overlay requests
    std::unordered_map<uint64_t, Pending> pending_;

    // Timers
    boost::asio::steady_timer t_keepalive_;
    boost::asio::steady_timer t_shuffle_;
    boost::asio::steady_timer t_repair_;
    boost::asio::steady_timer t_pending_;
    boost::asio::steady_timer t_neighbor_set_;
    boost::asio::steady_timer t_housekeeping_;

    // RNG
    mutable std::mt19937 rng_{std::random_device{}()};

    // Neighbor file tracking
    std::string neighbors_snapshot_;
    std::unordered_set<std::string> active_neighbor_set_;
};
