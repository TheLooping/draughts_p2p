#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/evp.h>

namespace draughts {
namespace crypto {

using Byte = unsigned char;
static constexpr std::size_t kAesKeySize = 16;
static constexpr std::size_t kAesIvSize = 16;
static constexpr std::size_t kSm2CoordSize = 32;
static constexpr std::size_t kSm2PubKeySize = 64; // X || Y

using Key = std::array<Byte, kAesKeySize>;
using Iv = std::array<Byte, kAesIvSize>;
using PubKey = std::array<Byte, kSm2PubKeySize>;

class AesCtr final {
public:
    static void TransformInPlace(Byte* data, std::size_t len, const Key& key, const Iv& iv);
    static std::vector<Byte> Transform(const std::vector<Byte>& input, const Key& key, const Iv& iv);
};

class Sm2KeyPair final {
public:
    Sm2KeyPair();
    ~Sm2KeyPair();

    Sm2KeyPair(const Sm2KeyPair&) = delete;
    Sm2KeyPair& operator=(const Sm2KeyPair&) = delete;

    Sm2KeyPair(Sm2KeyPair&&) noexcept;
    Sm2KeyPair& operator=(Sm2KeyPair&&) noexcept;

    PubKey public_key_raw() const;
    std::vector<Byte> DeriveSharedSecret(const PubKey& peer_public_key_raw) const;

    static std::pair<Key, Iv> DeriveKeyAndIv(const std::vector<Byte>& shared_secret);

private:
    struct PkeyDeleter {
        void operator()(EVP_PKEY* p) const noexcept;
    };
    using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

    PkeyPtr key_pair_;
};

} // namespace crypto
} // namespace draughts

