#include "cli.hpp"

#include <cctype>
#include <iostream>
#include <sstream>
#include <termios.h>
#include <unistd.h>

namespace {

static inline std::string ltrim(std::string s) {
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    s.erase(0, i);
    return s;
}

static inline std::string rtrim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

static inline std::string trim_ws(std::string s) {
    return rtrim(ltrim(std::move(s)));
}

static void print_help(Console& c) {
    c.println("commands:");
    c.println("  help                         show this help");
    c.println("  id                           show node id / endpoint");
    c.println("  neighbors                    show active neighbor list");
    c.println("  twohop                       show cached 2-hop neighbor info");
    c.println("  peers                        show known peers (directory)");
    c.println("  inbox                        list received messages");
    c.println("  requests                     list pending responder sessions");
    c.println("  send <peer_id|ipv4:port> <text> send message to responder");
    c.println("  reply <session_hex> <text>    reply to a received request");
    c.println("  quit                          exit");
}

static bool read_line(Console& c, std::string& out) {
    out.clear();
    if (!::isatty(STDIN_FILENO)) {
        return static_cast<bool>(std::getline(std::cin, out));
    }

    termios orig{};
    if (::tcgetattr(STDIN_FILENO, &orig) != 0) {
        return static_cast<bool>(std::getline(std::cin, out));
    }
    termios raw = orig;
    raw.c_lflag &= static_cast<unsigned int>(~(ICANON | ECHO));
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        return static_cast<bool>(std::getline(std::cin, out));
    }

    auto restore = [&]() { ::tcsetattr(STDIN_FILENO, TCSANOW, &orig); };
    char ch = 0;
    while (true) {
        ssize_t n = ::read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            restore();
            return false;
        }
        if (ch == '\r' || ch == '\n') {
            c.print("\n");
            break;
        }
        if (ch == 0x7f || ch == '\b') {
            if (!out.empty()) {
                out.pop_back();
                c.print("\b \b");
            }
            continue;
        }
        if (ch == 0x03) {
            c.print("^C\n");
            restore();
            return false;
        }
        if (std::isprint(static_cast<unsigned char>(ch))) {
            out.push_back(ch);
            c.print(std::string(1, ch));
        }
    }
    restore();
    return true;
}

} // namespace

Cli::Cli(boost::asio::io_context& io, DraughtsNode& node, DraughtsApp& app, Console& console)
    : io_(io), node_(node), app_(app), console_(console) {}

void Cli::start() {
    th_ = std::thread([this]{ run(); });
}

void Cli::join() {
    if (th_.joinable()) th_.join();
}

void Cli::run() {
    print_help(console_);

    std::string line;
    while (!stop_.load()) {
        console_.print("draughts> ");
        if (!read_line(console_, line)) break;
        line = trim_ws(line);
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "help" || cmd == "h" || cmd == "?") {
            print_help(console_);
            continue;
        }

        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            stop_.store(true);
            boost::asio::post(io_, [this]{ node_.stop(); app_.stop(); });
            break;
        }

        if (cmd == "id") {
            boost::asio::post(io_, [this]{ node_.cmd_show_id(); });
            continue;
        }
        if (cmd == "neighbors" || cmd == "nbr") {
            boost::asio::post(io_, [this]{ node_.cmd_show_neighbors(); });
            continue;
        }
        if (cmd == "twohop") {
            boost::asio::post(io_, [this]{ node_.cmd_show_twohop(); });
            continue;
        }
        if (cmd == "peers") {
            boost::asio::post(io_, [this]{ node_.cmd_show_peers(); });
            continue;
        }
        if (cmd == "inbox") {
            boost::asio::post(io_, [this]{ app_.cmd_inbox(); });
            continue;
        }
        if (cmd == "requests") {
            boost::asio::post(io_, [this]{ app_.cmd_requests(); });
            continue;
        }

        if (cmd == "send") {
            std::string ipv4;
            iss >> ipv4;
            std::string rest;
            std::getline(iss, rest);
            rest = trim_ws(rest);
            if (ipv4.empty() || rest.empty()) {
                console_.println("usage: send <peer_id|ipv4:port> <text>");
                continue;
            }
            boost::asio::post(io_, [this, ipv4, rest]{ app_.cmd_send(ipv4, rest); });
            continue;
        }

        if (cmd == "reply") {
            std::string sid;
            iss >> sid;
            std::string rest;
            std::getline(iss, rest);
            rest = trim_ws(rest);
            if (sid.empty() || rest.empty()) {
                console_.println("usage: reply <session_hex> <text>");
                continue;
            }
            boost::asio::post(io_, [this, sid, rest]{ app_.cmd_reply(sid, rest); });
            continue;
        }

        console_.println("unknown command: " + cmd);
    }
}
