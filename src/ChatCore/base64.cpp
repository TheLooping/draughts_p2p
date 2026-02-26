#include "base64.hpp"

#include <openssl/evp.h>

#include <stdexcept>

namespace b64 {

std::string encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    // Base64 length is 4*ceil(n/3)
    std::string out;
    out.resize(4 * ((data.size() + 2) / 3));
    int n = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        reinterpret_cast<const unsigned char*>(data.data()),
        static_cast<int>(data.size()));
    if (n < 0) throw std::runtime_error("EVP_EncodeBlock failed");
    out.resize(static_cast<size_t>(n));
    return out;
}

std::vector<uint8_t> decode(const std::string& s) {
    if (s.empty()) return {};
    // Maximum decoded length is 3*(n/4)
    std::vector<uint8_t> out;
    out.resize(3 * (s.size() / 4) + 4);

    int n = EVP_DecodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(s.data()),
        static_cast<int>(s.size()));
    if (n < 0) throw std::runtime_error("EVP_DecodeBlock failed");

    // EVP_DecodeBlock doesn't account for '=' padding bytes in returned length.
    size_t pad = 0;
    if (!s.empty() && s.back() == '=') pad++;
    if (s.size() >= 2 && s[s.size()-2] == '=') pad++;

    size_t real = static_cast<size_t>(n);
    if (pad > 0 && real >= pad) real -= pad;
    out.resize(real);
    return out;
}

} // namespace b64
