#pragma once

#include <boost/asio.hpp>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "config.hpp"
#include "crypto/Crypto.h"
#include "logger.hpp"

class TopodClient {
public:
    struct HopInfo {
        std::string peer_id;
        boost::asio::ip::address_v4 addr;
        uint16_t port = 0;
        draughts::crypto::PubKey pubkey{};
    };

    struct RoutePlan {
        std::uint64_t term = 0;
        HopInfo nh;
        HopInfo nnh;
    };

    struct StateView {
        std::uint64_t term = 0;
        std::vector<std::string> active_peer_ids;
    };

    struct TwoHopView {
        std::uint64_t term = 0;
        std::vector<std::string> active_peer_ids;
        std::unordered_map<std::string, std::vector<std::string>> twohop_peer_ids;
    };

    TopodClient(const Config& cfg, Logger& logger);

    bool enabled() const;

    bool pick_route(const std::string& exclude_peer_id, RoutePlan& out) const;
    bool pick_history_nnh(const std::string& nh_peer_id,
                          std::uint64_t term,
                          const std::string& exclude_peer_id,
                          bool strict,
                          HopInfo& out) const;
    bool query_state(StateView& out) const;
    bool query_twohop(TwoHopView& out) const;

private:
    bool exchange(const std::string& request, std::string& response) const;
    static bool parse_line(const std::string& line,
                           std::string& status,
                           std::unordered_map<std::string, std::string>& kv);
    bool parse_hop(const std::unordered_map<std::string, std::string>& kv,
                   const std::string& prefix,
                   HopInfo& out) const;

private:
    std::string socket_path_;
    std::uint32_t timeout_ms_ = 1500;
    Logger& logger_;
};
