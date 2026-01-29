#pragma once

#include <fstream>
#include <mutex>
#include <string>

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
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

private:
    void log(LogLevel lvl, const std::string& msg);
    static std::string ts();
    static const char* level_str(LogLevel lvl);

    std::mutex mu_;
    std::ofstream out_;
    LogLevel level_ = LogLevel::INFO;
};
