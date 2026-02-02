#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <array>
#include <vector>

#include "tlv.hpp"

namespace proto {

static constexpr uint8_t kVersion = 1;

// Envelope: version(u8) type(u8) nonce(u64) payload_len(u32) payload_bytes
enum class MsgType : uint8_t {
    // HyParView (overlay maintenance)
    JOIN = 1,
    FORWARD_JOIN = 2,
    JOIN_ACCEPT = 3,
    PING = 4,
    PONG = 5,
    VIEW_UPDATE = 6,
    VIEW_UPDATE_REQ = 7,

    // Application
    APP_PACKET = 20
};

struct PeerDescriptor {
    std::string peer_id;
    std::array<std::uint8_t, 4> ip{}; // IPv4 bytes
    uint16_t overlay_port = 0;
    uint16_t draughts_port = 0;
    std::string pubkey;             // base64(DER) public key
    uint64_t incarnation = 1;
    uint64_t seq = 1;
    std::unordered_map<std::string, tlv::Bytes> meta; // extensible

    tlv::Bytes to_tlv() const;
    static PeerDescriptor from_tlv(const tlv::Bytes& b);
};

struct Message {
    MsgType type{};
    uint64_t nonce{};
    tlv::Bytes payload;
};

tlv::Bytes encode(const Message& m);
Message decode(const tlv::Bytes& datagram);

// Payload helpers
// JOIN: [DESC]
Message make_join(uint64_t nonce, const PeerDescriptor& d);
// FORWARD_JOIN: [TTL(u16)] [DESC]
Message make_forward_join(uint64_t nonce, uint16_t ttl, const PeerDescriptor& d);

// JOIN_ACCEPT: [DESC]
Message make_join_accept(uint64_t nonce, const PeerDescriptor& my_desc);

// PING/PONG: [DESC]
Message make_ping(uint64_t nonce, const PeerDescriptor& my_desc);
Message make_pong(uint64_t nonce, const PeerDescriptor& my_desc);

// VIEW_UPDATE: [SENDER_DESC] [NEIGHBOR_DESC...]
Message make_view_update(uint64_t nonce,
                         const PeerDescriptor& sender,
                         const std::vector<PeerDescriptor>& neighbors);

// VIEW_UPDATE_REQ: [DESC]
Message make_view_update_req(uint64_t nonce, const PeerDescriptor& sender);

// Tags for descriptor TLVs
enum DescTag : uint16_t {
    PEER_ID = 1,
    ADDR = 2, // IPv4 bytes (4)
    PUBKEY = 3,
    INCARNATION = 4,
    SEQ = 5,
    OVERLAY_PORT = 6,
    DRAUGHTS_PORT = 7,
    META_KV = 200
};

// Tags for message payload TLVs
enum MsgTag : uint16_t {
    // overlay tags
    TTL = 10,
    DESC = 13,
    NEIGHBOR = 16,

    // app tags (>= 100)
    PKT_ID = 100,
    FLAGS = 101,
    RW_TTL = 102,
    DEST_ID = 103,
    DEST_ADDR = 104,
    NNH_ID = 105,
    ORIG_PKT_ID = 106,
    EPHEM_PUBKEY_DER = 107,
    IV_DATA = 108,
    CIPHERTEXT = 109,
    RTOKEN_BLOB = 110,
    IV_TOKEN_SR = 111,
    IV_TOKEN_FR = 112,
    FINAL_RELAY_ID = 113,
    RELAY_SAMPLE = 114
};

} // namespace proto
