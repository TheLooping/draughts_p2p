#pragma once

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <fstream>
#include <list>
#include <mutex>
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

    bool start();
    void stop();

    // CLI actions
    void cmd_send(const std::string& dest, const std::string& text);
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

    struct InitiatorSession {
        draughts::crypto::Sm2KeyPair init_key;
        draughts::crypto::PubKey resp_pub{};
        uint64_t created_ms = 0;
    };

    struct ResponderValue {
        boost::asio::ip::address_v4 addr_ph;
        uint16_t port_ph = 0;
        draughts::crypto::PubKey pk_pph_tmp;
        draughts::crypto::PubKey pk_init_tmp;
        boost::asio::ip::address_v4 addr_nnh;
        uint16_t port_nnh = 0;
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
    std::string peer_label_for(const boost::asio::ip::address_v4& addr, uint16_t port) const;
    void init_trace();
    std::string trace_store_key(const std::string& pem, const std::string& prefix);
    std::string trace_store_pub_raw(const draughts::crypto::PubKey& raw);
    void trace_initiator_transform(const char* stage,
                                   const char* flow,
                                   const char* field,
                                   const std::string& sid,
                                   const std::uint8_t before[draughts::kAddrSize],
                                   const std::uint8_t after[draughts::kAddrSize],
                                   const draughts::crypto::Sm2KeyPair& priv_key,
                                   const draughts::crypto::PubKey& peer_pub);
    bool transform_initiator_addr(std::uint8_t addr[draughts::kAddrSize],
                                  const draughts::crypto::Sm2KeyPair& priv_key,
                                  const draughts::crypto::PubKey& peer_pub,
                                  const char* stage,
                                  const char* flow,
                                  const char* field,
                                  const std::string& sid);

    bool send_packet_to(const draughts::DraughtsPacket& p,
                        const boost::asio::ip::address_v4& addr,
                        uint16_t port);

    bool pick_nh_nnh(boost::asio::ip::address_v4& nh_addr,
                     uint16_t& nh_port,
                     draughts::crypto::PubKey& nh_pub,
                     boost::asio::ip::address_v4& nnh_addr,
                     uint16_t& nnh_port,
                     draughts::crypto::PubKey& nnh_pub,
                     const std::string& exclude_peer_id);
    bool pick_nnh_for_peer_id(const std::string& nh_peer_id,
                              const std::string& exclude_peer_id,
                              boost::asio::ip::address_v4& nnh_addr,
                              uint16_t& nnh_port,
                              draughts::crypto::PubKey& nnh_pub);

    static std::string session_hex(const std::string& sid);
    static std::string bytes_to_hex(const uint8_t* data, size_t len);

    static std::string addr_to_string(const boost::asio::ip::address_v4& addr);
    static std::string endpoint_to_string(const boost::asio::ip::address_v4& addr, uint16_t port);
    static bool addr_from_string(const std::string& s, boost::asio::ip::address_v4& out);
    static bool endpoint_from_string(const std::string& s, boost::asio::ip::address_v4& out, uint16_t& port);
    static void addr_to_bytes(const boost::asio::ip::address_v4& addr,
                              uint16_t port,
                              std::uint8_t out_bytes[draughts::kAddrSize]);
    static bool bytes_to_addr(const std::uint8_t in_bytes[draughts::kAddrSize],
                              boost::asio::ip::address_v4& out,
                              uint16_t& port);

    static std::string session_id_from_bytes(const std::uint8_t bytes[draughts::kSessionIdSize]);
    void random_session_id(std::uint8_t out[draughts::kSessionIdSize]);

    static void encode_payload(const std::string& text, std::uint8_t out[draughts::kDataSize]);
    static bool decode_payload(const std::uint8_t in[draughts::kDataSize], std::string& text);

    bool get_peer_pubkey_by_endpoint(const boost::asio::ip::address_v4& addr,
                                     uint16_t port,
                                     draughts::crypto::PubKey& out_pubkey) const;
    bool resolve_peer_target(const std::string& dest,
                             boost::asio::ip::address_v4& out_addr,
                             uint16_t& out_port,
                             draughts::crypto::PubKey& out_pubkey,
                             std::string& out_peer_id) const;

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
    std::unordered_map<std::string, InitiatorSession> initiator_sessions_;
    std::ofstream trace_out_;
    std::mutex trace_mu_;
    std::unordered_map<std::string, std::string> trace_key_cache_;
    std::string trace_dir_;
    bool trace_ready_ = false;
    ResponderLru responder_lru_;

    std::vector<InboxItem> inbox_;

    Ciplc ciplc_;

    boost::asio::steady_timer t_housekeeping_;
    mutable std::mt19937 rng_{std::random_device{}()};

    static constexpr size_t kResponderLruCapacity = 256;
};
