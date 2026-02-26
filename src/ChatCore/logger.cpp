#include "logger.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

Logger::Logger(const std::string& path, LogLevel lvl) : level_(lvl) {
    open(path);
}

bool Logger::open(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    out_.open(path, std::ios::out | std::ios::app);
    return out_.is_open();
}

void Logger::set_level(LogLevel lvl) {
    level_ = lvl;
}

void Logger::debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
void Logger::info(const std::string& msg) { log(LogLevel::INFO, msg); }
void Logger::warn(const std::string& msg) { log(LogLevel::WARN, msg); }
void Logger::error(const std::string& msg) { log(LogLevel::ERROR, msg); }

const char* Logger::level_str(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        default: return "?";
    }
}

std::string Logger::ts() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;

    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms;
    return oss.str();
}

void Logger::log(LogLevel lvl, const std::string& msg) {
    if (static_cast<int>(lvl) < static_cast<int>(level_)) return;
    std::lock_guard<std::mutex> lk(mu_);
    if (!out_.is_open()) return;
    out_ << ts() << " [" << level_str(lvl) << "] " << msg << "\n";
    out_.flush();
}
