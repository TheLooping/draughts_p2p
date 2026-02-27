#pragma once

#include <fstream>
#include <mutex>
#include <string>

enum class LogLevel {
    DETAIL = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4
};

// Simple thread-safe file logger.
// - No stdout logging (CLI stays clean)
class Logger {
public:
    Logger() = default;
    explicit Logger(const std::string& path, LogLevel lvl = LogLevel::INFO);

    bool open(const std::string& path);
    void set_level(LogLevel lvl);

    void debug(const std::string& msg);
    void info(const std::string& msg);
    void warn(const std::string& msg);
    void error(const std::string& msg);
    void detail(const std::string& msg);

    void debug(const std::string& tag, const std::string& msg);
    void info(const std::string& tag, const std::string& msg);
    void warn(const std::string& tag, const std::string& msg);
    void error(const std::string& tag, const std::string& msg);
    void detail(const std::string& tag, const std::string& msg);

private:
    void log(LogLevel lvl, const std::string& msg);
    void log(LogLevel lvl, const std::string& tag, const std::string& msg);
    static std::string ts();
    static const char* level_en(LogLevel lvl);
    static std::string infer_tag(const std::string& msg);
    static std::string normalize_tag(const std::string& tag);

    std::mutex mu_;
    std::ofstream out_;
    LogLevel level_ = LogLevel::INFO;
};
