#include "tlv.hpp"

namespace tlv {

static void ensure(const Bytes& in, size_t off, size_t need) {
    if (off + need > in.size()) throw std::runtime_error("TLV parse: truncated");
}

void write_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
void write_u32(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
void write_u64(Bytes& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((v >> (8*i)) & 0xFF));
}

uint16_t read_u16(const Bytes& in, size_t& off) {
    ensure(in, off, 2);
    uint16_t v = (static_cast<uint16_t>(in[off]) << 8) | static_cast<uint16_t>(in[off+1]);
    off += 2;
    return v;
}
uint32_t read_u32(const Bytes& in, size_t& off) {
    ensure(in, off, 4);
    uint32_t v = (static_cast<uint32_t>(in[off]) << 24) |
                 (static_cast<uint32_t>(in[off+1]) << 16) |
                 (static_cast<uint32_t>(in[off+2]) << 8) |
                 (static_cast<uint32_t>(in[off+3]));
    off += 4;
    return v;
}
uint64_t read_u64(const Bytes& in, size_t& off) {
    ensure(in, off, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<uint64_t>(in[off+i]);
    off += 8;
    return v;
}

void write_tlv(Bytes& out, uint16_t tag, const Bytes& val) {
    if (val.size() > 0xFFFF) throw std::runtime_error("TLV: value too large");
    write_u16(out, tag);
    write_u16(out, static_cast<uint16_t>(val.size()));
    out.insert(out.end(), val.begin(), val.end());
}
void write_tlv_str(Bytes& out, uint16_t tag, const std::string& s) {
    write_tlv(out, tag, str_bytes(s));
}
void write_tlv_u64(Bytes& out, uint16_t tag, uint64_t v) {
    Bytes b;
    write_u64(b, v);
    write_tlv(out, tag, b);
}

std::vector<Item> parse_all(const Bytes& in) {
    std::vector<Item> items;
    size_t off = 0;
    while (off < in.size()) {
        ensure(in, off, 4);
        uint16_t tag = read_u16(in, off);
        uint16_t len = read_u16(in, off);
        ensure(in, off, len);
        Bytes val(in.begin()+off, in.begin()+off+len);
        off += len;
        items.push_back(Item{tag, std::move(val)});
    }
    return items;
}

Bytes str_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}
std::string bytes_str(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

} // namespace tlv
