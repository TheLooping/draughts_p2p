#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/Crypto.h"

namespace crypto {

using Key = draughts::crypto::Key;
using Iv = draughts::crypto::Iv;
using Byte = draughts::crypto::Byte;

class CommutativeCipher final {
public:
    static void TransformInPlace(Byte* data, std::size_t len, const Key& key, const Iv& iv);
    static std::vector<Byte> Transform(const std::vector<Byte>& input, const Key& key, const Iv& iv);
};

} // namespace crypto

