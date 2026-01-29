#include "cipher.hpp"

namespace crypto {

void CommutativeCipher::TransformInPlace(Byte* data, std::size_t len, const Key& key, const Iv& iv) {
    draughts::crypto::AesCtr::TransformInPlace(data, len, key, iv);
}

std::vector<Byte> CommutativeCipher::Transform(const std::vector<Byte>& input, const Key& key, const Iv& iv) {
    return draughts::crypto::AesCtr::Transform(input, key, iv);
}

} // namespace crypto

