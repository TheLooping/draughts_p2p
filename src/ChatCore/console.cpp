#include "console.hpp"

#include <iostream>

void Console::println(const std::string& s) {
    std::lock_guard<std::mutex> lk(mu_);
    std::cout << s << std::endl;
}

void Console::print(const std::string& s) {
    std::lock_guard<std::mutex> lk(mu_);
    std::cout << s;
    std::cout.flush();
}
