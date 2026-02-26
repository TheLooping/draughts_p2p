#include "app_packet.hpp"

#include <cstring>
#include <algorithm>

namespace app {

static tlv::Bytes u8_bytes(uint8_t v) {
    return tlv::Bytes{v};
}

static tlv::Bytes u16_bytes(uint16_t v) {
    tlv::Bytes b;
    tlv::write_u16(b, v);
    return b;
}

static std::optional<crypto::Iv> to_arr16(const tlv::Bytes& b) {
    if (b.size() != 16) return std::nullopt;
    crypto::Iv a{};
    std::memcpy(a.data(), b.data(), 16);
    return a;
}

tlv::Bytes encode(const AppPacket& p) {
    tlv::Bytes out;

    tlv::write_tlv_u64(out, proto::MsgTag::PKT_ID, p.pkt_id);
    tlv::write_tlv(out, proto::MsgTag::FLAGS, u8_bytes(p.flags));
    tlv::write_tlv(out, proto::MsgTag::RW_TTL, u16_bytes(p.ttl));

    if (!p.dest_id.empty()) tlv::write_tlv_str(out, proto::MsgTag::DEST_ID, p.dest_id);
    if (!p.dest_addr.empty()) tlv::write_tlv_str(out, proto::MsgTag::DEST_ADDR, p.dest_addr);
    if (!p.nnh_id.empty()) tlv::write_tlv_str(out, proto::MsgTag::NNH_ID, p.nnh_id);

    if (p.flags & FLAG_REPLY) {
        tlv::write_tlv_u64(out, proto::MsgTag::ORIG_PKT_ID, p.orig_pkt_id);
    }

    if (!p.eph_pubkey_der.empty()) tlv::write_tlv(out, proto::MsgTag::EPHEM_PUBKEY_DER, p.eph_pubkey_der);

    tlv::write_tlv(out, proto::MsgTag::IV_DATA, tlv::Bytes(p.iv_data.begin(), p.iv_data.end()));
    if (!p.ciphertext.empty()) tlv::write_tlv(out, proto::MsgTag::CIPHERTEXT, p.ciphertext);

    if (!p.rtoken.blob.empty()) {
        tlv::write_tlv(out, proto::MsgTag::RTOKEN_BLOB, p.rtoken.blob);
        tlv::write_tlv(out, proto::MsgTag::IV_TOKEN_SR, tlv::Bytes(p.rtoken.iv_sr.begin(), p.rtoken.iv_sr.end()));
        if (!std::all_of(p.rtoken.iv_fr.begin(), p.rtoken.iv_fr.end(), [](uint8_t x){ return x==0; })) {
            tlv::write_tlv(out, proto::MsgTag::IV_TOKEN_FR, tlv::Bytes(p.rtoken.iv_fr.begin(), p.rtoken.iv_fr.end()));
        }
    }

    if (!p.final_relay_id.empty()) {
        tlv::write_tlv_str(out, proto::MsgTag::FINAL_RELAY_ID, p.final_relay_id);
    }

    for (const auto& d : p.relay_sample) {
        tlv::write_tlv(out, proto::MsgTag::RELAY_SAMPLE, d.to_tlv());
    }

    return out;
}

std::optional<AppPacket> decode(const tlv::Bytes& payload) {
    AppPacket p;

    auto items = tlv::parse_all(payload);
    for (auto& it : items) {
        switch (it.tag) {
            case proto::MsgTag::PKT_ID: {
                size_t off = 0;
                p.pkt_id = tlv::read_u64(it.value, off);
            } break;
            case proto::MsgTag::FLAGS: {
                if (!it.value.empty()) p.flags = it.value[0];
            } break;
            case proto::MsgTag::RW_TTL: {
                size_t off = 0;
                p.ttl = tlv::read_u16(it.value, off);
            } break;
            case proto::MsgTag::DEST_ID: p.dest_id = tlv::bytes_str(it.value); break;
            case proto::MsgTag::DEST_ADDR: p.dest_addr = tlv::bytes_str(it.value); break;
            case proto::MsgTag::NNH_ID: p.nnh_id = tlv::bytes_str(it.value); break;
            case proto::MsgTag::ORIG_PKT_ID: {
                size_t off = 0;
                p.orig_pkt_id = tlv::read_u64(it.value, off);
            } break;
            case proto::MsgTag::EPHEM_PUBKEY_DER: p.eph_pubkey_der = it.value; break;
            case proto::MsgTag::IV_DATA: {
                auto a = to_arr16(it.value);
                if (!a) return std::nullopt;
                p.iv_data = *a;
            } break;
            case proto::MsgTag::CIPHERTEXT: p.ciphertext = it.value; break;
            case proto::MsgTag::RTOKEN_BLOB: p.rtoken.blob = it.value; break;
            case proto::MsgTag::IV_TOKEN_SR: {
                auto a = to_arr16(it.value);
                if (!a) return std::nullopt;
                p.rtoken.iv_sr = *a;
            } break;
            case proto::MsgTag::IV_TOKEN_FR: {
                auto a = to_arr16(it.value);
                if (!a) return std::nullopt;
                p.rtoken.iv_fr = *a;
            } break;
            case proto::MsgTag::FINAL_RELAY_ID: p.final_relay_id = tlv::bytes_str(it.value); break;
            case proto::MsgTag::RELAY_SAMPLE: {
                p.relay_sample.push_back(proto::PeerDescriptor::from_tlv(it.value));
            } break;
            default: break;
        }
    }

    if (p.pkt_id == 0) return std::nullopt;
    if (p.dest_addr.empty()) {
        const bool ok = ((p.flags & FLAG_REPLY) != 0) && !p.rtoken.blob.empty();
        if (!ok) return std::nullopt;
    }
    return p;
}

} // namespace app
