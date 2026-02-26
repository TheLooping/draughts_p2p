#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace b64 {

// Base64 encode / decode helpers (OpenSSL).
std::string encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> decode(const std::string& s);

} // namespace b64
