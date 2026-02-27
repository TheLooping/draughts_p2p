#include "topod_client.hpp"

#include "base64.hpp"
#include "draughts_packet.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <unordered_set>
#include <vector>

namespace {

std::string trim(const std::string& s) {
    std::size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    std::size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::string token;
    std::unordered_set<std::string> seen;
    for (char c : s) {
        if (c == ',') {
            token = trim(token);
            if (!token.empty() && seen.insert(token).second) out.push_back(token);
            token.clear();
            continue;
        }
        token.push_back(c);
    }
    token = trim(token);
    if (!token.empty() && seen.insert(token).second) out.push_back(token);
    return out;
}

} // namespace

TopodClient::TopodClient(const Config& cfg, Logger& logger)
    : socket_path_(cfg.topod_ipc_socket),
      timeout_ms_(cfg.topod_timeout_ms == 0 ? 1500u : cfg.topod_timeout_ms),
      logger_(logger) {}

bool TopodClient::enabled() const {
    return !socket_path_.empty();
}

bool TopodClient::pick_route(const std::string& exclude_peer_id, RoutePlan& out) const {
    if (!enabled()) return false;
    std::string req = "PLAN";
    if (!exclude_peer_id.empty()) req += " exclude=" + exclude_peer_id;

    std::string resp;
    if (!exchange(req, resp)) return false;

    std::string status;
    std::unordered_map<std::string, std::string> kv;
    if (!parse_line(resp, status, kv)) {
        logger_.warn("topod PLAN 响应解析失败: " + resp);
        return false;
    }
    if (status != "OK") {
        logger_.warn("topod PLAN failed: " + resp);
        return false;
    }

    auto it_term = kv.find("term");
    if (it_term == kv.end()) return false;
    std::uint64_t term = 0;
    try {
        term = static_cast<std::uint64_t>(std::stoull(it_term->second));
    } catch (...) {
        return false;
    }

    RoutePlan plan{};
    plan.term = term;
    if (!parse_hop(kv, "nh", plan.nh)) return false;
    if (!parse_hop(kv, "nnh", plan.nnh)) return false;
    out = std::move(plan);
    return true;
}

bool TopodClient::pick_history_nnh(const std::string& nh_peer_id,
                                   std::uint64_t term,
                                   const std::string& exclude_peer_id,
                                   bool strict,
                                   HopInfo& out) const {
    if (!enabled()) return false;
    if (nh_peer_id.empty() || term == 0) return false;

    std::string req = "HISTORY peer=" + nh_peer_id + " term=" + std::to_string(term);
    if (!exclude_peer_id.empty()) req += " exclude=" + exclude_peer_id;
    req += std::string(" strict=") + (strict ? "1" : "0");

    std::string resp;
    if (!exchange(req, resp)) return false;

    std::string status;
    std::unordered_map<std::string, std::string> kv;
    if (!parse_line(resp, status, kv)) {
        logger_.warn("topod HISTORY 响应解析失败: " + resp);
        return false;
    }
    if (status == "NOT_FOUND") return false;
    if (status != "OK") {
        logger_.warn("topod HISTORY failed: " + resp);
        return false;
    }
    return parse_hop(kv, "nnh", out);
}

bool TopodClient::query_state(StateView& out) const {
    if (!enabled()) return false;

    std::string resp;
    if (!exchange("STATE", resp)) return false;

    std::string status;
    std::unordered_map<std::string, std::string> kv;
    if (!parse_line(resp, status, kv)) {
        logger_.warn("topod STATE 响应解析失败: " + resp);
        return false;
    }
    if (status != "OK") {
        logger_.warn("topod STATE failed: " + resp);
        return false;
    }

    auto it_term = kv.find("term");
    auto it_active = kv.find("active");
    if (it_term == kv.end() || it_active == kv.end()) return false;

    std::uint64_t term = 0;
    try {
        term = static_cast<std::uint64_t>(std::stoull(it_term->second));
    } catch (...) {
        return false;
    }

    StateView st{};
    st.term = term;
    st.active_peer_ids = split_csv(it_active->second);
    out = std::move(st);
    return true;
}

bool TopodClient::query_twohop(TwoHopView& out) const {
    if (!enabled()) return false;

    std::string resp;
    if (!exchange("TWOHOP", resp)) return false;

    std::string status;
    std::unordered_map<std::string, std::string> kv;
    if (!parse_line(resp, status, kv)) {
        logger_.warn("topod TWOHOP 响应解析失败: " + resp);
        return false;
    }
    if (status != "OK") {
        logger_.warn("topod TWOHOP failed: " + resp);
        return false;
    }

    auto it_term = kv.find("term");
    auto it_active = kv.find("active");
    if (it_term == kv.end() || it_active == kv.end()) return false;

    std::uint64_t term = 0;
    try {
        term = static_cast<std::uint64_t>(std::stoull(it_term->second));
    } catch (...) {
        return false;
    }

    TwoHopView view{};
    view.term = term;
    view.active_peer_ids = split_csv(it_active->second);
    for (const auto& nh : view.active_peer_ids) {
        if (nh.empty()) continue;
        view.twohop_peer_ids.emplace(nh, std::vector<std::string>{});
    }

    auto it_twohop = kv.find("twohop");
    if (it_twohop != kv.end() && !it_twohop->second.empty()) {
        std::istringstream entries(it_twohop->second);
        std::string token;
        while (std::getline(entries, token, ';')) {
            token = trim(token);
            if (token.empty()) continue;
            auto pos = token.find('>');
            if (pos == std::string::npos) continue;
            std::string nh = trim(token.substr(0, pos));
            std::string nnh_csv = token.substr(pos + 1);
            if (nh.empty()) continue;
            view.twohop_peer_ids[nh] = split_csv(nnh_csv);
        }
    }

    out = std::move(view);
    return true;
}

bool TopodClient::exchange(const std::string& request, std::string& response) const {
    if (!enabled()) return false;
    auto start = std::chrono::steady_clock::now();
    logger_.info("topod IPC 请求开始: socket=" + socket_path_ + " req=\"" + request + "\"");
    if (socket_path_.size() >= sizeof(sockaddr_un::sun_path)) {
        logger_.warn("topod socket path too long");
        return false;
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        logger_.warn(std::string("topod socket() failed: ") + std::strerror(errno));
        return false;
    }

    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout_ms_ / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms_ % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path_.c_str());

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        logger_.warn("topod connect failed: " + socket_path_ + " err=" + std::strerror(errno));
        ::close(fd);
        return false;
    }

    std::string payload = request + "\n";
    std::size_t sent = 0;
    while (sent < payload.size()) {
        ssize_t n = ::send(fd, payload.data() + sent, payload.size() - sent, 0);
        if (n <= 0) {
            logger_.warn("topod send failed req=\"" + request + "\" err=" + std::strerror(errno));
            ::close(fd);
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }

    std::string line;
    char ch = 0;
    while (true) {
        ssize_t n = ::recv(fd, &ch, 1, 0);
        if (n < 0) {
            logger_.warn("topod recv failed req=\"" + request + "\" err=" + std::strerror(errno));
            break;
        }
        if (n == 0) break;
        if (ch == '\n') break;
        line.push_back(ch);
    }
    ::close(fd);

    line = trim(line);
    if (line.empty()) {
        logger_.warn("topod 响应为空 req=\"" + request + "\"");
        return false;
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    logger_.info("topod IPC 请求完成: elapsed=" + std::to_string(elapsed.count()) +
                 "ms req=\"" + request + "\" resp=\"" + line + "\"");
    response = std::move(line);
    return true;
}

bool TopodClient::parse_line(const std::string& line,
                             std::string& status,
                             std::unordered_map<std::string, std::string>& kv) {
    kv.clear();
    status.clear();
    std::istringstream iss(line);
    if (!(iss >> status)) return false;
    std::string tok;
    while (iss >> tok) {
        auto pos = tok.find('=');
        if (pos == std::string::npos) continue;
        auto key = tok.substr(0, pos);
        auto val = tok.substr(pos + 1);
        kv.emplace(std::move(key), std::move(val));
    }
    return true;
}

bool TopodClient::parse_hop(const std::unordered_map<std::string, std::string>& kv,
                            const std::string& prefix,
                            HopInfo& out) const {
    auto key_id = prefix + "_id";
    auto key_ip = prefix + "_ip";
    auto key_port = prefix + "_port";
    auto key_pub = prefix + "_pub";

    auto it_id = kv.find(key_id);
    auto it_ip = kv.find(key_ip);
    auto it_port = kv.find(key_port);
    auto it_pub = kv.find(key_pub);
    if (it_id == kv.end() || it_ip == kv.end() || it_port == kv.end() || it_pub == kv.end()) return false;

    boost::system::error_code ec;
    auto addr = boost::asio::ip::address_v4::from_string(it_ip->second, ec);
    if (ec) return false;

    int port_i = 0;
    try {
        port_i = std::stoi(it_port->second);
    } catch (...) {
        return false;
    }
    if (port_i <= 0 || port_i > 65535) return false;

    std::vector<uint8_t> raw;
    try {
        raw = b64::decode(it_pub->second);
    } catch (...) {
        return false;
    }
    if (raw.size() != draughts::kPkSize) return false;

    HopInfo h{};
    h.peer_id = it_id->second;
    h.addr = addr;
    h.port = static_cast<uint16_t>(port_i);
    std::memcpy(h.pubkey.data(), raw.data(), draughts::kPkSize);
    out = std::move(h);
    return true;
}
