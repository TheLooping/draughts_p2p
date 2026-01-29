#include "protocol.hpp"
#include <algorithm>
#include <stdexcept>

namespace proto {

tlv::Bytes PeerDescriptor::to_tlv() const {
    tlv::Bytes out;
    tlv::write_tlv_str(out, DescTag::PEER_ID, peer_id);
    tlv::write_tlv(out, DescTag::ADDR, tlv::Bytes(ip.begin(), ip.end()));
    tlv::Bytes ob; tlv::write_u16(ob, overlay_port);
    tlv::write_tlv(out, DescTag::OVERLAY_PORT, ob);
    tlv::Bytes db; tlv::write_u16(db, draughts_port);
    tlv::write_tlv(out, DescTag::DRAUGHTS_PORT, db);
    if (!pubkey.empty()) tlv::write_tlv_str(out, DescTag::PUBKEY, pubkey);
    tlv::write_tlv_u64(out, DescTag::INCARNATION, incarnation);
    tlv::write_tlv_u64(out, DescTag::SEQ, seq);

    // meta kv: value = [klen:u16][kbytes][vlen:u32][vbytes]
    for (const auto& kv : meta) {
        tlv::Bytes v;
        const auto& k = kv.first;
        const auto& vb = kv.second;
        if (k.size() > 0xFFFF) continue;
        tlv::write_u16(v, static_cast<uint16_t>(k.size()));
        v.insert(v.end(), k.begin(), k.end());
        if (vb.size() > 0xFFFFFFFFu) continue;
        tlv::write_u32(v, static_cast<uint32_t>(vb.size()));
        v.insert(v.end(), vb.begin(), vb.end());
        tlv::write_tlv(out, DescTag::META_KV, v);
    }
    return out;
}

PeerDescriptor PeerDescriptor::from_tlv(const tlv::Bytes& b) {
    PeerDescriptor d;
    bool addr_set = false;
    auto items = tlv::parse_all(b);
    for (auto& it : items) {
        switch (it.tag) {
            case DescTag::PEER_ID: d.peer_id = tlv::bytes_str(it.value); break;
            case DescTag::ADDR: {
                if (it.value.size() != d.ip.size()) break;
                std::copy(it.value.begin(), it.value.end(), d.ip.begin());
                addr_set = true;
            } break;
            case DescTag::OVERLAY_PORT: {
                size_t off = 0; d.overlay_port = tlv::read_u16(it.value, off);
            } break;
            case DescTag::DRAUGHTS_PORT: {
                size_t off = 0; d.draughts_port = tlv::read_u16(it.value, off);
            } break;
            case DescTag::PUBKEY: d.pubkey = tlv::bytes_str(it.value); break;
            case DescTag::INCARNATION: {
                size_t off = 0; d.incarnation = tlv::read_u64(it.value, off);
            } break;
            case DescTag::SEQ: {
                size_t off = 0; d.seq = tlv::read_u64(it.value, off);
            } break;
            case DescTag::META_KV: {
                size_t off = 0;
                uint16_t klen = tlv::read_u16(it.value, off);
                if (off + klen > it.value.size()) break;
                std::string k(reinterpret_cast<const char*>(it.value.data()+off), klen);
                off += klen;
                uint32_t vlen = tlv::read_u32(it.value, off);
                if (off + vlen > it.value.size()) break;
                tlv::Bytes vb(it.value.begin()+off, it.value.begin()+off+vlen);
                d.meta.emplace(std::move(k), std::move(vb));
            } break;
            default: break;
        }
    }
    if (d.peer_id.empty()) throw std::runtime_error("descriptor missing peer_id");
    if (!addr_set) throw std::runtime_error("descriptor missing addr");
    if (d.overlay_port == 0 || d.draughts_port == 0) {
        throw std::runtime_error("descriptor missing ports");
    }
    return d;
}

static void write_envelope(tlv::Bytes& out, MsgType type, uint64_t nonce, const tlv::Bytes& payload) {
    out.push_back(kVersion);
    out.push_back(static_cast<uint8_t>(type));
    tlv::write_u64(out, nonce);
    if (payload.size() > 0xFFFFFFFFu) throw std::runtime_error("payload too large");
    tlv::write_u32(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
}

tlv::Bytes encode(const Message& m) {
    tlv::Bytes out;
    write_envelope(out, m.type, m.nonce, m.payload);
    return out;
}

Message decode(const tlv::Bytes& datagram) {
    if (datagram.size() < 1 + 1 + 8 + 4) throw std::runtime_error("datagram too small");
    size_t off = 0;
    uint8_t ver = datagram[off++];
    if (ver != kVersion) throw std::runtime_error("version mismatch");
    MsgType type = static_cast<MsgType>(datagram[off++]);
    uint64_t nonce = tlv::read_u64(datagram, off);
    uint32_t plen = tlv::read_u32(datagram, off);
    if (off + plen > datagram.size()) throw std::runtime_error("truncated payload");
    tlv::Bytes payload(datagram.begin()+off, datagram.begin()+off+plen);
    return Message{type, nonce, std::move(payload)};
}

static tlv::Bytes payload_desc_only(const PeerDescriptor& d) {
    tlv::Bytes p;
    tlv::write_tlv(p, MsgTag::DESC, d.to_tlv());
    return p;
}

Message make_join(uint64_t nonce, const PeerDescriptor& d) {
    return Message{MsgType::JOIN, nonce, payload_desc_only(d)};
}

Message make_forward_join(uint64_t nonce, uint16_t ttl, const PeerDescriptor& d) {
    tlv::Bytes p;
    tlv::Bytes ttlb;
    tlv::write_u16(ttlb, ttl);
    tlv::write_tlv(p, MsgTag::TTL, ttlb);
    tlv::write_tlv(p, MsgTag::DESC, d.to_tlv());
    return Message{MsgType::FORWARD_JOIN, nonce, std::move(p)};
}

Message make_add_req(uint64_t nonce, uint32_t lease_ms, const PeerDescriptor& d) {
    tlv::Bytes p;
    tlv::Bytes lb; tlv::write_u32(lb, lease_ms);
    tlv::write_tlv(p, MsgTag::LEASE_MS, lb);
    tlv::write_tlv(p, MsgTag::DESC, d.to_tlv());
    return Message{MsgType::ADD_REQ, nonce, std::move(p)};
}

Message make_add_ack(uint64_t nonce, bool accept, uint32_t lease_ms,
                     const PeerDescriptor& my_desc,
                     const std::vector<PeerDescriptor>& referrals) {
    tlv::Bytes p;
    tlv::Bytes ab; ab.push_back(static_cast<uint8_t>(accept ? 1 : 0));
    tlv::write_tlv(p, MsgTag::ACCEPT, ab);
    tlv::Bytes lb; tlv::write_u32(lb, lease_ms);
    tlv::write_tlv(p, MsgTag::LEASE_MS, lb);
    tlv::write_tlv(p, MsgTag::DESC, my_desc.to_tlv());
    for (const auto& r : referrals) tlv::write_tlv(p, MsgTag::REFERRAL, r.to_tlv());
    return Message{MsgType::ADD_ACK, nonce, std::move(p)};
}

Message make_keepalive(uint64_t nonce, uint32_t lease_ms, const PeerDescriptor& my_desc) {
    tlv::Bytes p;
    tlv::Bytes lb; tlv::write_u32(lb, lease_ms);
    tlv::write_tlv(p, MsgTag::LEASE_MS, lb);
    tlv::write_tlv(p, MsgTag::DESC, my_desc.to_tlv());
    return Message{MsgType::KEEPALIVE, nonce, std::move(p)};
}

Message make_remove_notice(uint64_t nonce, const std::string& reason) {
    tlv::Bytes p;
    tlv::write_tlv_str(p, MsgTag::REASON, reason);
    return Message{MsgType::REMOVE_NOTICE, nonce, std::move(p)};
}

Message make_shuffle_req(uint64_t nonce, const std::vector<PeerDescriptor>& sample) {
    tlv::Bytes p;
    for (const auto& d : sample) tlv::write_tlv(p, MsgTag::DESC, d.to_tlv());
    return Message{MsgType::SHUFFLE_REQ, nonce, std::move(p)};
}

Message make_shuffle_resp(uint64_t nonce, const std::vector<PeerDescriptor>& sample) {
    tlv::Bytes p;
    for (const auto& d : sample) tlv::write_tlv(p, MsgTag::DESC, d.to_tlv());
    return Message{MsgType::SHUFFLE_RESP, nonce, std::move(p)};
}

Message make_neighbor_set(uint64_t nonce, const PeerDescriptor& sender, const std::vector<PeerDescriptor>& neighbors) {
    tlv::Bytes p;
    tlv::write_tlv(p, MsgTag::DESC, sender.to_tlv());
    for (const auto& d : neighbors) {
        tlv::write_tlv(p, MsgTag::NEIGHBOR, d.to_tlv());
    }
    return Message{MsgType::NEIGHBOR_SET, nonce, std::move(p)};
}

} // namespace proto
