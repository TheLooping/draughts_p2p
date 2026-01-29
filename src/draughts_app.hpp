#pragma once

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ciplc.hpp"
#include "config.hpp"
#include "console.hpp"
#include "crypto/Crypto.h"
#include "draughts_packet.hpp"
#include "logger.hpp"
#include "node.hpp"

class DraughtsApp {
public:
    DraughtsApp(boost::asio::io_context& io,
                Config cfg,
                DraughtsNode& node,
                draughts::crypto::Sm2KeyPair identity,
                Logger& logger,
                Console& console);

    void start();
    void stop();

    // CLI actions
    void cmd_send(const std::string& dest_ipv4, const std::string& text);
    void cmd_inbox();
    void cmd_requests();
    void cmd_reply(const std::string& session_hex, const std::string& text);

private:
    using udp = boost::asio::ip::udp;

    struct InboxItem {
        bool is_reply = false;
        std::string session_hex;
        std::string text;
        std::string from_addr;
    };

    struct ResponderValue {
        boost::asio::ip::address_v4 addr_ph;
        uint16_t port_ph = 0;
        draughts::crypto::PubKey pk_pph_tmp;
        draughts::crypto::PubKey pk_init_tmp;
        boost::asio::ip::address_v4 addr_nnh;
        std::array<std::uint8_t, draughts::kAddrSize> c_addr_init{};
        uint64_t created_ms = 0;
    };

    class ResponderLru {
    public:
        struct Entry {
            std::string sid;
            ResponderValue value;
        };

        explicit ResponderLru(size_t capacity);

        void insert_head(const std::string& sid, const ResponderValue& value);
        bool get_first_and_move_to_tail(const std::string& sid, ResponderValue& out);
        size_t size() const;
        size_t capacity() const;
        std::vector<std::pair<std::string, size_t>> session_counts() const;

    private:
        void evict_if_needed();

        std::list<Entry> lru_;
        std::unordered_map<std::string, std::deque<std::list<Entry>::iterator>> index_;
        size_t capacity_ = 0;
    };

    void do_receive();
    void on_datagram(const std::array<uint8_t, draughts::kPacketSize>& bytes,
                     const udp::endpoint& from);

    void handle_exit_packet(draughts::DraughtsPacket& p, const udp::endpoint& from);
    void handle_random_walk(draughts::DraughtsPacket& p, const udp::endpoint& from);

    bool decrypt_params(draughts::DraughtsPacket& p);
    bool encrypt_params_for_next_hop(draughts::DraughtsPacket& p,
                                     const draughts::crypto::PubKey& next_pubkey,
                                     const draughts::crypto::Sm2KeyPair& ph_keypair);

    bool send_packet_to(const draughts::DraughtsPacket& p,
                        const boost::asio::ip::address_v4& addr,
                        uint16_t port);

    bool pick_nh_nnh(boost::asio::ip::address_v4& nh_addr,
                     uint16_t& nh_port,
                     draughts::crypto::PubKey& nh_pub,
                     boost::asio::ip::address_v4& nnh_addr,
                     draughts::crypto::PubKey& nnh_pub,
                     const std::string& exclude_peer_id);
    bool pick_nnh_for_peer_id(const std::string& nh_peer_id,
                              const std::string& exclude_peer_id,
                              boost::asio::ip::address_v4& nnh_addr,
                              draughts::crypto::PubKey& nnh_pub);

    static std::string session_hex(const std::string& sid);
    static std::string bytes_to_hex(const uint8_t* data, size_t len);

    static std::string addr_to_string(const boost::asio::ip::address_v4& addr);
    static bool addr_from_string(const std::string& s, boost::asio::ip::address_v4& out);
    static void addr_to_bytes(const boost::asio::ip::address_v4& addr, std::uint8_t out_bytes[draughts::kAddrSize]);
    static bool bytes_to_addr(const std::uint8_t in_bytes[draughts::kAddrSize], boost::asio::ip::address_v4& out);

    static std::string session_id_from_bytes(const std::uint8_t bytes[draughts::kSessionIdSize]);
    void random_session_id(std::uint8_t out[draughts::kSessionIdSize]);

    static void encode_payload(const std::string& text, std::uint8_t out[draughts::kDataSize]);
    static bool decode_payload(const std::uint8_t in[draughts::kDataSize], std::string& text);

    bool get_peer_pubkey_by_addr(const boost::asio::ip::address_v4& addr,
                                 draughts::crypto::PubKey& out_pubkey) const;
    bool get_peer_draughts_port_by_addr(const boost::asio::ip::address_v4& addr,
                                        uint16_t& out_port) const;

    void prune_sessions();

private:
    boost::asio::io_context& io_;
    Config cfg_;
    DraughtsNode& node_;
    draughts::crypto::Sm2KeyPair identity_;
    Logger& logger_;
    Console& console_;

    udp::socket sock_;
    udp::endpoint remote_;
    std::array<uint8_t, draughts::kPacketSize> rxbuf_{};

    std::unordered_set<std::string> initiator_session_ids_;
    ResponderLru responder_lru_;

    std::vector<InboxItem> inbox_;

    Ciplc ciplc_;

    boost::asio::steady_timer t_housekeeping_;
    mutable std::mt19937 rng_{std::random_device{}()};

    static constexpr size_t kResponderLruCapacity = 256;
};
