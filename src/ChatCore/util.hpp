#pragma once
#include <cstdint>
#include <random>
#include <chrono>
#include <string>
#include <cctype>

inline uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

inline uint64_t rand_u64() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    return rng();
}

inline std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) b--;
    return s.substr(a, b-a);
}
