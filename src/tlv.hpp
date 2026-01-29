#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <stdexcept>

namespace tlv {

// Simple TLV: [tag:u16][len:u16][value:bytes]
using Bytes = std::vector<uint8_t>;

void write_u16(Bytes& out, uint16_t v);
void write_u32(Bytes& out, uint32_t v);
void write_u64(Bytes& out, uint64_t v);
uint16_t read_u16(const Bytes& in, size_t& off);
uint32_t read_u32(const Bytes& in, size_t& off);
uint64_t read_u64(const Bytes& in, size_t& off);

void write_tlv(Bytes& out, uint16_t tag, const Bytes& val);
void write_tlv_str(Bytes& out, uint16_t tag, const std::string& s);
void write_tlv_u64(Bytes& out, uint16_t tag, uint64_t v);

struct Item {
    uint16_t tag{};
    Bytes value{};
};

std::vector<Item> parse_all(const Bytes& in);

// helpers
Bytes str_bytes(const std::string& s);
std::string bytes_str(const Bytes& b);

} // namespace tlv
