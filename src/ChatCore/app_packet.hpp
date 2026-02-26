#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cipher.hpp"
#include "protocol.hpp"
#include "tlv.hpp"

namespace app {

// Flags in AppPacket.flags
static constexpr uint8_t FLAG_REPLY = 0x01;  // packet is a reply
static constexpr uint8_t FLAG_FINAL = 0x02;  // packet is a final delivery (to dest)

struct ReplyToken {
    tlv::Bytes blob;   // ciphertext
    crypto::Iv iv_sr{}; // IV for sender<->receiver layer
    crypto::Iv iv_fr{}; // IV for final-relay layer (added on delivery)
};

struct AppPacket {
    uint64_t pkt_id = 0;
    uint8_t flags = 0;
    uint16_t ttl = 0;

    // Destination info (this demo uses ipv4:port for delivery)
    std::string dest_id;    // optional/human readable
    std::string dest_addr;  // "ip:port" (required for delivery except reply bootstrap)

    // Next-next-hop peer id (chosen by previous hop). Receiver forwards to this if continuing.
    std::string nnh_id;

    // Reply-only: id of the original forward packet.
    uint64_t orig_pkt_id = 0;

    // End-to-end encryption material
    tlv::Bytes eph_pubkey_der;  // sender ephemeral pubkey (DER)
    crypto::Iv iv_data{};       // IV for ciphertext
    tlv::Bytes ciphertext;

    // Anonymous reply token
    ReplyToken rtoken;

    // Filled by final relay when delivering forward packet
    std::string final_relay_id;

    // Optional: final relay shares its active neighbor sample so the receiver can pick NNH for reply bootstrap
    std::vector<proto::PeerDescriptor> relay_sample;
};

tlv::Bytes encode(const AppPacket& p);
std::optional<AppPacket> decode(const tlv::Bytes& payload);

}  // namespace app
