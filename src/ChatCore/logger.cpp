#include "logger.hpp"

#include <chrono>
#include <cctype>
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

void Logger::detail(const std::string& msg) { log(LogLevel::DETAIL, msg); }
void Logger::debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
void Logger::info(const std::string& msg) { log(LogLevel::INFO, msg); }
void Logger::warn(const std::string& msg) { log(LogLevel::WARN, msg); }
void Logger::error(const std::string& msg) { log(LogLevel::ERROR, msg); }

void Logger::detail(const std::string& tag, const std::string& msg) { log(LogLevel::DETAIL, tag, msg); }
void Logger::debug(const std::string& tag, const std::string& msg) { log(LogLevel::DEBUG, tag, msg); }
void Logger::info(const std::string& tag, const std::string& msg) { log(LogLevel::INFO, tag, msg); }
void Logger::warn(const std::string& tag, const std::string& msg) { log(LogLevel::WARN, tag, msg); }
void Logger::error(const std::string& tag, const std::string& msg) { log(LogLevel::ERROR, tag, msg); }

const char* Logger::level_en(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::DETAIL: return "DETAIL";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        default: return "?";
    }
}

std::string Logger::normalize_tag(const std::string& tag) {
    std::string out = tag;
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.front()))) out.erase(out.begin());
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) out.pop_back();
    if (out.empty()) return "General";
    std::size_t cut = out.find_first_of(" \t");
    if (cut != std::string::npos) {
        out = out.substr(0, cut);
    }
    if (out.empty()) return "General";
    return out;
}

std::string Logger::infer_tag(const std::string& msg) {
    std::string low = msg;
    for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (low.find("cli ") != std::string::npos || low.find("cli_") != std::string::npos) {
        return "CLI 命令";
    }
    if (low.find("topod") != std::string::npos || low.find("ipc") != std::string::npos) {
        return "IPC 调用";
    }
    if (low.find("recv") != std::string::npos || msg.find("收到") != std::string::npos) {
        return "Packet 收包";
    }
    if (low.find("send") != std::string::npos || msg.find("转发") != std::string::npos) {
        return "Packet 发包";
    }
    if (low.find("start") != std::string::npos || low.find("stop") != std::string::npos ||
        msg.find("启动") != std::string::npos || msg.find("停止") != std::string::npos) {
        return "Lifecycle 生命周期";
    }
    if (low.find("error") != std::string::npos || low.find("failed") != std::string::npos ||
        low.find("invalid") != std::string::npos || low.find("mismatch") != std::string::npos ||
        msg.find("失败") != std::string::npos || msg.find("错误") != std::string::npos) {
        return "Failure 异常";
    }
    return "General 通用";
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
    log(lvl, infer_tag(msg), msg);
}

void Logger::log(LogLevel lvl, const std::string& tag, const std::string& msg) {
    if (static_cast<int>(lvl) < static_cast<int>(level_)) return;
    std::lock_guard<std::mutex> lk(mu_);
    if (!out_.is_open()) return;
    out_ << ts()
         << " [" << level_en(lvl) << "]"
         << " [" << normalize_tag(tag) << "] "
         << msg << "\n";
    out_.flush();
}
