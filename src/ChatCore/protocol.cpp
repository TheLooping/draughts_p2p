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

} // namespace proto
