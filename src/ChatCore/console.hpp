#pragma once

#include <mutex>
#include <string>

// Thread-safe console output for user interaction.
// NOTE: This is NOT used for internal logs.
class Console {
public:
    void println(const std::string& s);
    void print(const std::string& s);

private:
    std::mutex mu_;
};
