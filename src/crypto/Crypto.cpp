#include "Crypto.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

namespace draughts {
namespace crypto {
namespace {

inline void EnsureOpenSslInitialized() {
    static const int kInitOnce = []() -> int {
        OPENSSL_init_crypto(0, nullptr);
        return 1;
    }();
    (void)kInitOnce;
}

std::string GetOpenSslErrorString() {
    std::string out;
    for (;;) {
        unsigned long err = ERR_get_error();
        if (err == 0) break;
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!out.empty()) out += " | ";
        out += buf;
    }
    return out.empty() ? std::string("unknown OpenSSL error") : out;
}

[[noreturn]] void ThrowOpenSslError(const char* where) {
    throw std::runtime_error(std::string(where) + ": " + GetOpenSslErrorString());
}

inline void CheckSizeFitsInt(std::size_t n, const char* what) {
    if (n > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error(std::string(what) + " too large for OpenSSL int length");
    }
}

EVP_PKEY* sm2_keypair_new() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) ThrowOpenSslError("EVP_PKEY_CTX_new_id");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> guard(pctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_keygen_init(pctx) != 1) ThrowOpenSslError("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) != 1) {
        ThrowOpenSslError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid(NID_sm2)");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        ThrowOpenSslError("EVP_PKEY_keygen");
    }
    return pkey;
}

PubKey ec_pubkey_raw(const EVP_PKEY* pkey) {
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) ThrowOpenSslError("EVP_PKEY_get0_EC_KEY");

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const EC_POINT* point = EC_KEY_get0_public_key(ec);
    if (!group || !point) ThrowOpenSslError("EC_KEY_get0_public_key");

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_new(), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_new(), BN_free);
    if (!x || !y) ThrowOpenSslError("BN_new");

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x.get(), y.get(), nullptr) != 1) {
        ThrowOpenSslError("EC_POINT_get_affine_coordinates_GFp");
    }

    PubKey out{};
    if (BN_bn2binpad(x.get(), out.data(), kSm2CoordSize) != static_cast<int>(kSm2CoordSize)) {
        ThrowOpenSslError("BN_bn2binpad(x)");
    }
    if (BN_bn2binpad(y.get(), out.data() + kSm2CoordSize, kSm2CoordSize) != static_cast<int>(kSm2CoordSize)) {
        ThrowOpenSslError("BN_bn2binpad(y)");
    }
    return out;
}

EVP_PKEY* sm2_from_raw_pubkey(const PubKey& raw) {
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec(EC_KEY_new_by_curve_name(NID_sm2), EC_KEY_free);
    if (!ec) ThrowOpenSslError("EC_KEY_new_by_curve_name(NID_sm2)");

    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
    if (!group) ThrowOpenSslError("EC_KEY_get0_group");

    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(group), EC_POINT_free);
    if (!point) ThrowOpenSslError("EC_POINT_new");

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_bin2bn(raw.data(), kSm2CoordSize, nullptr), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_bin2bn(raw.data() + kSm2CoordSize, kSm2CoordSize, nullptr), BN_free);
    if (!x || !y) ThrowOpenSslError("BN_bin2bn");

    if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), x.get(), y.get(), nullptr) != 1) {
        ThrowOpenSslError("EC_POINT_set_affine_coordinates_GFp");
    }
    if (EC_KEY_set_public_key(ec.get(), point.get()) != 1) {
        ThrowOpenSslError("EC_KEY_set_public_key");
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) ThrowOpenSslError("EVP_PKEY_new");
    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1) {
        EVP_PKEY_free(pkey);
        ThrowOpenSslError("EVP_PKEY_assign_EC_KEY");
    }
    return pkey;
}

} // namespace

// ---------------- AesCtr ----------------

void AesCtr::TransformInPlace(Byte* data, std::size_t len, const Key& key, const Iv& iv) {
    if (!data || len == 0) return;
    EnsureOpenSslInitialized();
    CheckSizeFitsInt(len, "AES-CTR input size");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) ThrowOpenSslError("EVP_CIPHER_CTX_new");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> guard(ctx, EVP_CIPHER_CTX_free);

    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv.data(), 1) != 1) {
        ThrowOpenSslError("EVP_CipherInit_ex(aes_128_ctr)");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len1 = 0;
    if (EVP_CipherUpdate(ctx, data, &out_len1, data, static_cast<int>(len)) != 1) {
        ThrowOpenSslError("EVP_CipherUpdate(ctr)");
    }

    int out_len2 = 0;
    if (EVP_CipherFinal_ex(ctx, data + out_len1, &out_len2) != 1) {
        ThrowOpenSslError("EVP_CipherFinal_ex(ctr)");
    }
}

std::vector<Byte> AesCtr::Transform(const std::vector<Byte>& input, const Key& key, const Iv& iv) {
    std::vector<Byte> out = input;
    if (!out.empty()) TransformInPlace(out.data(), out.size(), key, iv);
    return out;
}

// ---------------- Sm2KeyPair ----------------

void Sm2KeyPair::PkeyDeleter::operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }

Sm2KeyPair::Sm2KeyPair() : key_pair_(nullptr) {
    EnsureOpenSslInitialized();
    key_pair_.reset(sm2_keypair_new());
}

Sm2KeyPair::~Sm2KeyPair() = default;

Sm2KeyPair::Sm2KeyPair(Sm2KeyPair&& other) noexcept : key_pair_(std::move(other.key_pair_)) {}

Sm2KeyPair& Sm2KeyPair::operator=(Sm2KeyPair&& other) noexcept {
    if (this != &other) key_pair_ = std::move(other.key_pair_);
    return *this;
}

PubKey Sm2KeyPair::public_key_raw() const {
    if (!key_pair_) throw std::runtime_error("SM2 keypair not initialized");
    return ec_pubkey_raw(key_pair_.get());
}

std::vector<Byte> Sm2KeyPair::DeriveSharedSecret(const PubKey& peer_public_key_raw) const {
    if (!key_pair_) throw std::runtime_error("SM2 keypair not initialized");

    EVP_PKEY* peer = sm2_from_raw_pubkey(peer_public_key_raw);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer_guard(peer, EVP_PKEY_free);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key_pair_.get(), nullptr);
    if (!ctx) ThrowOpenSslError("EVP_PKEY_CTX_new");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx_guard(ctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_derive_init(ctx) != 1) ThrowOpenSslError("EVP_PKEY_derive_init");
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) ThrowOpenSslError("EVP_PKEY_derive_set_peer");

    std::size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1 || secret_len == 0) {
        ThrowOpenSslError("EVP_PKEY_derive(size)");
    }

    std::vector<Byte> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) != 1) {
        ThrowOpenSslError("EVP_PKEY_derive(data)");
    }
    secret.resize(secret_len);
    return secret;
}

std::pair<Key, Iv> Sm2KeyPair::DeriveKeyAndIv(const std::vector<Byte>& shared_secret) {
    EnsureOpenSslInitialized();
    if (shared_secret.empty()) throw std::runtime_error("shared secret is empty");
    CheckSizeFitsInt(shared_secret.size(), "HKDF input size");

    static const char kInfo[] = "Draughts-SM2-ECDH-AES-CTR";
    std::array<Byte, kAesKeySize + kAesIvSize> okm;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) ThrowOpenSslError("EVP_PKEY_CTX_new_id(HKDF)");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx_guard(pctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_derive_init(pctx) != 1) ThrowOpenSslError("EVP_PKEY_derive_init(HKDF)");
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) ThrowOpenSslError("EVP_PKEY_CTX_set_hkdf_md");
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) != 1) ThrowOpenSslError("EVP_PKEY_CTX_set1_hkdf_salt");
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret.data(), static_cast<int>(shared_secret.size())) != 1) {
        ThrowOpenSslError("EVP_PKEY_CTX_set1_hkdf_key");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(kInfo),
                                    static_cast<int>(sizeof(kInfo) - 1)) != 1) {
        ThrowOpenSslError("EVP_PKEY_CTX_add1_hkdf_info");
    }

    std::size_t out_len = okm.size();
    if (EVP_PKEY_derive(pctx, okm.data(), &out_len) != 1) {
        ThrowOpenSslError("EVP_PKEY_derive(HKDF)");
    }
    if (out_len != okm.size()) throw std::runtime_error("HKDF output length mismatch");

    Key key{};
    Iv iv{};
    std::copy(okm.begin(), okm.begin() + kAesKeySize, key.begin());
    std::copy(okm.begin() + kAesKeySize, okm.end(), iv.begin());
    return {key, iv};
}

} // namespace crypto
} // namespace draughts

