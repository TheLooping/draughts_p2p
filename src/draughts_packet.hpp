#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace draughts {

static constexpr std::size_t kPacketSize = 1280;
static constexpr std::size_t kPkSize = 64;
static constexpr std::size_t kAddrSize = 6; // IPv4 (4) + port (2)
static constexpr std::size_t kSessionIdSize = 16;
static constexpr std::size_t kDataSize = 1038;

#pragma pack(push, 1)
struct DraughtsParams {
    std::uint8_t pk_pph_tmp[kPkSize];
    std::uint8_t pk_init_tmp[kPkSize];
    std::uint8_t addr_nnh[kAddrSize];
    std::uint8_t c_addr_real_receiver[kAddrSize];
    std::uint8_t c_addr_real_sender[kAddrSize];
    double x;
    std::uint64_t magic_num;
};

struct DraughtsPacket {
    std::uint8_t pk_ph_tmp[kPkSize];
    DraughtsParams params;
    std::uint8_t session_id[kSessionIdSize];
    std::uint8_t c_data[kDataSize];
};
#pragma pack(pop)

static_assert(sizeof(DraughtsParams) == 162, "DraughtsParams size mismatch");
static_assert(sizeof(DraughtsPacket) == kPacketSize, "DraughtsPacket size mismatch");

inline bool is_exit_pk(const std::uint8_t pk[kPkSize]) {
    for (std::size_t i = 0; i < kPkSize; ++i) {
        if (pk[i] != 0xEE) return false;
    }
    return true;
}

inline void fill_exit_pk(std::uint8_t pk[kPkSize]) {
    std::memset(pk, 0xEE, kPkSize);
}

inline void zero_pk(std::uint8_t pk[kPkSize]) {
    std::memset(pk, 0, kPkSize);
}

inline void zero_addr(std::uint8_t addr[kAddrSize]) {
    std::memset(addr, 0, kAddrSize);
}

inline bool is_zero_addr(const std::uint8_t addr[kAddrSize]) {
    for (std::size_t i = 0; i < kAddrSize; ++i) {
        if (addr[i] != 0) return false;
    }
    return true;
}

} // namespace draughts
