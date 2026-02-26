#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <array>
#include <vector>

#include "tlv.hpp"

namespace proto {

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

// Tags for application packet TLVs
enum MsgTag : uint16_t {
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
