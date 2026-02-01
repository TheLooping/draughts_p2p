#include "node.hpp"

#include "util.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

using boost::asio::ip::make_address_v4;

namespace {

using boost::asio::ip::address_v4;

address_v4 addr_from_bytes(const std::array<std::uint8_t, 4>& b) {
    address_v4::bytes_type bytes{};
    std::copy(b.begin(), b.end(), bytes.begin());
    return address_v4(bytes);
}

std::array<std::uint8_t, 4> bytes_from_addr(const address_v4& addr) {
    auto bytes = addr.to_bytes();
    return {bytes[0], bytes[1], bytes[2], bytes[3]};
}

std::string overlay_key(const address_v4& addr, uint16_t port) {
    return addr.to_string() + ":" + std::to_string(port);
}

std::string draughts_key(const address_v4& addr, uint16_t port) {
    return addr.to_string() + ":" + std::to_string(port);
}

std::string peer_to_string(const proto::PeerDescriptor& d) {
    auto addr = addr_from_bytes(d.ip);
    std::ostringstream oss;
    oss << addr.to_string() << ":" << d.overlay_port << ":" << d.draughts_port;
    return oss.str();
}

std::optional<boost::asio::ip::udp::endpoint> overlay_endpoint_for(const proto::PeerDescriptor& d) {
    if (d.overlay_port == 0) return std::nullopt;
    return boost::asio::ip::udp::endpoint(addr_from_bytes(d.ip), d.overlay_port);
}

struct BootstrapEntry {
    address_v4 addr;
    uint16_t overlay_port = 0;
    uint16_t draughts_port = 0;
};

std::optional<BootstrapEntry> parse_bootstrap(const std::string& s) {
    if (s.empty()) return std::nullopt;
    auto last = s.rfind(':');
    if (last == std::string::npos) return std::nullopt;
    auto mid = s.rfind(':', last - 1);
    if (mid == std::string::npos) return std::nullopt;

    std::string ip = s.substr(0, mid);
    std::string overlay_ps = s.substr(mid + 1, last - mid - 1);
    std::string draughts_ps = s.substr(last + 1);
    if (ip.empty() || overlay_ps.empty() || draughts_ps.empty()) return std::nullopt;

    boost::system::error_code ec;
    auto addr = address_v4::from_string(ip, ec);
    if (ec) return std::nullopt;

    int overlay_port_i = 0;
    int draughts_port_i = 0;
    try {
        overlay_port_i = std::stoi(overlay_ps);
        draughts_port_i = std::stoi(draughts_ps);
    } catch (...) {
        return std::nullopt;
    }
    if (overlay_port_i <= 0 || overlay_port_i > 65535) return std::nullopt;
    if (draughts_port_i <= 0 || draughts_port_i > 65535) return std::nullopt;

    uint16_t overlay_port = static_cast<uint16_t>(overlay_port_i);
    uint16_t draughts_port = static_cast<uint16_t>(draughts_port_i);

    return BootstrapEntry{addr, overlay_port, draughts_port};
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

struct PeerInfoFile {
    std::string peer_id;
    std::string bind_ip;
    uint16_t overlay_port = 0;
    uint16_t draughts_port = 0;
    std::string pubkey;
};

bool load_peer_info_file(const std::string& path, PeerInfoFile& out) {
    std::ifstream in(path);
    if (!in.is_open()) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));
        if (key == "peer_id") out.peer_id = val;
        else if (key == "bind_ip") out.bind_ip = val;
        else if (key == "overlay_port") out.overlay_port = static_cast<uint16_t>(std::stoul(val));
        else if (key == "draughts_port") out.draughts_port = static_cast<uint16_t>(std::stoul(val));
        else if (key == "pubkey") out.pubkey = val;
    }
    return !out.peer_id.empty() && !out.bind_ip.empty() && out.draughts_port != 0 && !out.pubkey.empty();
}

bool load_peer_descriptor(const std::string& peer_id,
                          const std::string& peer_info_dir,
                          proto::PeerDescriptor& out) {
    if (peer_info_dir.empty()) return false;
    PeerInfoFile info;
    std::string path = peer_info_dir + "/" + peer_id + ".info";
    if (!load_peer_info_file(path, info)) return false;
    boost::system::error_code ec;
    auto addr = address_v4::from_string(info.bind_ip, ec);
    if (ec) return false;
    out.peer_id = info.peer_id;
    out.ip = bytes_from_addr(addr);
    out.overlay_port = info.overlay_port;
    out.draughts_port = info.draughts_port;
    out.pubkey = info.pubkey;
    return true;
}

std::vector<std::string> load_neighbors_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return {};
    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        for (char& c : line) {
            if (c == ',') c = ' ';
        }
        std::stringstream ss(line);
        std::string token;
        while (ss >> token) {
            if (!seen.insert(token).second) continue;
            out.push_back(token);
        }
    }
    return out;
}

} // namespace

DraughtsNode::DraughtsNode(boost::asio::io_context& io,
                           Config cfg,
                           proto::PeerDescriptor self,
                           Logger& logger,
                           Console& console)
    : io_(io),
      cfg_(std::move(cfg)),
      self_(std::move(self)),
      logger_(logger),
      console_(console),
      sock_(io_),
      views_(cfg_.passive_max, cfg_.active_max),
      t_keepalive_(io_),
      t_shuffle_(io_),
      t_repair_(io_),
      t_pending_(io_),
      t_neighbor_set_(io_),
      t_housekeeping_(io_) {
}

bool DraughtsNode::start() {
    udp::endpoint bind_ep(make_address_v4(cfg_.bind_ip), cfg_.overlay_port);
    boost::system::error_code ec;
    sock_.open(udp::v4(), ec);
    if (ec) {
        logger_.error("failed to open overlay socket: " + ec.message());
        return false;
    }
    sock_.bind(bind_ep, ec);
    if (ec) {
        logger_.error("failed to bind overlay socket: " + ec.message() +
                      " (addr=" + cfg_.bind_ip + ":" + std::to_string(cfg_.overlay_port) + ")");
        return false;
    }

    auto local = sock_.local_endpoint();
    self_.ip = bytes_from_addr(local.address().to_v4());
    self_.overlay_port = local.port();
    self_.draughts_port = cfg_.draughts_port;

    logger_.info("node start peer_id=" + self_.peer_id + " bind=" + peer_to_string(self_));

    write_self_info_file();
    if (cfg_.static_topology) {
        if (!load_static_topology()) return false;
    }
    update_active_neighbors_file(true);
    do_receive();

    if (!cfg_.static_topology) {
        // Bootstrap
        for (const auto& b : cfg_.bootstraps) {
            auto be = parse_bootstrap(b);
            if (!be) {
                logger_.warn("invalid bootstrap: " + b);
                continue;
            }
            proto::Message m = proto::make_join(rand_u64(), self_);
            send_msg(m, udp::endpoint(be->addr, be->overlay_port));
        }

        tick_keepalive();
        tick_shuffle();
        tick_repair();
        tick_pending();
        tick_neighbor_set();
    }
    tick_housekeeping();
    return true;
}

void DraughtsNode::stop() {
    logger_.info("stop requested");
    remove_self_info_file();
    remove_active_neighbors_file();
    boost::system::error_code ec;
    sock_.close(ec);
    t_keepalive_.cancel();
    t_shuffle_.cancel();
    t_repair_.cancel();
    t_pending_.cancel();
    t_neighbor_set_.cancel();
    t_housekeeping_.cancel();
    io_.stop();
}

void DraughtsNode::cmd_show_id() {
    std::ostringstream oss;
    oss << "peer_id=" << self_.peer_id << " bind=" << peer_to_string(self_)
        << " active=" << views_.active_size() << "/" << cfg_.active_max
        << " passive=" << views_.passive_size() << "/" << cfg_.passive_max;
    console_.println(oss.str());
}

void DraughtsNode::cmd_show_neighbors() {
    auto act = views_.active_descriptors();
    std::ostringstream oss;
    oss << "Active neighbors (" << act.size() << "):";
    console_.println(oss.str());
    if (act.empty()) {
        console_.println("  (none)");
        return;
    }
    for (const auto& d : act) {
        console_.println("  - " + d.peer_id + " @ " + peer_to_string(d));
    }
}

void DraughtsNode::cmd_show_twohop() {
    console_.println("Two-hop cache entries: " + std::to_string(twohop_.size()));
    if (twohop_.empty()) {
        console_.println("  (empty)");
        return;
    }
    for (const auto& kv : twohop_) {
        const auto& peer = kv.first;
        const auto& e = kv.second;
        std::ostringstream oss;
        oss << "  * " << peer << " => " << e.neighbors.size() << " peers";
        console_.println(oss.str());
    }
}

void DraughtsNode::cmd_show_peers() {
    console_.println("Known peers (directory): " + std::to_string(directory_.size()));
    if (directory_.empty()) {
        console_.println("  (empty)");
        return;
    }
    size_t n = 0;
    for (const auto& kv : directory_) {
        const auto& d = kv.second;
        console_.println("  - " + d.peer_id + " @ " + peer_to_string(d));
        if (++n >= 50) {
            console_.println("  ... (truncated)");
            break;
        }
    }
}

std::vector<proto::PeerDescriptor> DraughtsNode::all_peers() const {
    std::vector<proto::PeerDescriptor> out;
    out.reserve(directory_.size());
    for (const auto& kv : directory_) {
        out.push_back(kv.second);
    }
    return out;
}

std::vector<proto::PeerDescriptor> DraughtsNode::active_neighbors() const {
    return views_.active_descriptors();
}

std::optional<proto::PeerDescriptor> DraughtsNode::lookup_peer(const std::string& peer_id) const {
    auto it = directory_.find(peer_id);
    if (it == directory_.end()) return std::nullopt;
    return it->second;
}

std::optional<proto::PeerDescriptor> DraughtsNode::lookup_peer_by_ipv4(const boost::asio::ip::address_v4& addr) const {
    auto bytes = addr.to_bytes();
    for (const auto& kv : directory_) {
        if (std::equal(bytes.begin(), bytes.end(), kv.second.ip.begin())) {
            return kv.second;
        }
    }
    return std::nullopt;
}

std::optional<proto::PeerDescriptor> DraughtsNode::lookup_peer_by_draughts_endpoint(
    const boost::asio::ip::address_v4& addr, uint16_t port) const {
    if (port == 0) return std::nullopt;
    auto it = draughts_addr_to_peer_id_.find(draughts_key(addr, port));
    if (it == draughts_addr_to_peer_id_.end()) return std::nullopt;
    auto pit = directory_.find(it->second);
    if (pit == directory_.end()) return std::nullopt;
    return pit->second;
}

// ------------------- UDP receive/send -------------------

void DraughtsNode::do_receive() {
    sock_.async_receive_from(boost::asio::buffer(rxbuf_), remote_,
                             [this](boost::system::error_code ec, std::size_t n) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted) {
                logger_.warn(std::string("recv error: ") + ec.message());
            }
            return;
        }
        tlv::Bytes bytes(rxbuf_.begin(), rxbuf_.begin() + n);
        on_datagram(bytes, remote_);
        do_receive();
    });
}

void DraughtsNode::on_datagram(const tlv::Bytes& bytes, const udp::endpoint& from) {
    proto::Message m;
    try {
        m = proto::decode(bytes);
    } catch (const std::exception& e) {
        logger_.warn(std::string("decode failed from ") + ep_to_string(from) + ": " + e.what());
        return;
    }

    if (cfg_.static_topology) {
        return;
    }

    switch (m.type) {
        case proto::MsgType::JOIN: handle_join(m.nonce, m.payload, from); break;
        case proto::MsgType::FORWARD_JOIN: handle_forward_join(m.nonce, m.payload, from); break;
        case proto::MsgType::ADD_REQ: handle_add_req(m.nonce, m.payload, from); break;
        case proto::MsgType::ADD_ACK: handle_add_ack(m.nonce, m.payload, from); break;
        case proto::MsgType::KEEPALIVE: handle_keepalive(m.nonce, m.payload, from); break;
        case proto::MsgType::SHUFFLE_REQ: handle_shuffle_req(m.nonce, m.payload, from); break;
        case proto::MsgType::SHUFFLE_RESP: handle_shuffle_resp(m.nonce, m.payload, from); break;
        case proto::MsgType::NEIGHBOR_SET: handle_neighbor_set(m.nonce, m.payload, from); break;
        default: break;
    }
}

void DraughtsNode::send_msg(const proto::Message& m, const udp::endpoint& to) {
    auto dat = proto::encode(m);
    if (m.type == proto::MsgType::APP_PACKET && cfg_.app_pad_to > 0 && dat.size() < cfg_.app_pad_to) {
        const size_t extra = cfg_.app_pad_to - dat.size();
        tlv::Bytes pad(extra);
        for (size_t i = 0; i < extra; ++i) pad[i] = static_cast<uint8_t>(rng_() & 0xFF);
        dat.insert(dat.end(), pad.begin(), pad.end());
    }

    auto buf = std::make_shared<tlv::Bytes>(std::move(dat));
    sock_.async_send_to(boost::asio::buffer(*buf), to, [buf](auto, auto) {});
}

// ------------------- Helpers -------------------

std::string DraughtsNode::ep_to_string(const udp::endpoint& ep) {
    return overlay_key(ep.address().to_v4(), ep.port());
}

void DraughtsNode::learn_peer(const proto::PeerDescriptor& d) {
    if (d.peer_id.empty()) return;
    if (d.peer_id == self_.peer_id) return;
    directory_[d.peer_id] = d;
    addr_to_peer_id_[overlay_key(addr_from_bytes(d.ip), d.overlay_port)] = d.peer_id;
    if (d.draughts_port != 0) {
        draughts_addr_to_peer_id_[draughts_key(addr_from_bytes(d.ip), d.draughts_port)] = d.peer_id;
    }
    views_.insert_passive(d);
}

std::optional<std::string> DraughtsNode::peer_id_from_endpoint(const udp::endpoint& ep) const {
    auto it = addr_to_peer_id_.find(overlay_key(ep.address().to_v4(), ep.port()));
    if (it == addr_to_peer_id_.end()) return std::nullopt;
    return it->second;
}

std::optional<proto::PeerDescriptor> DraughtsNode::pick_random_active_except(const std::string& exclude_peer_id) const {
    auto act = views_.active_descriptors();
    if (act.empty()) return std::nullopt;
    std::vector<proto::PeerDescriptor> candidates;
    candidates.reserve(act.size());
    for (const auto& d : act) {
        if (!exclude_peer_id.empty() && d.peer_id == exclude_peer_id) continue;
        candidates.push_back(d);
    }
    if (candidates.empty()) return std::nullopt;
    std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
    return candidates[dist(rng_)];
}

std::optional<std::string> DraughtsNode::pick_nnh_for(const std::string& nh_peer_id,
                                                     const std::string& exclude_peer_id) const {
    // Prefer two-hop cache entry for NH
    auto it = twohop_.find(nh_peer_id);
    if (it != twohop_.end()) {
        std::vector<std::string> c;
        for (const auto& d : it->second.neighbors) {
            if (d.peer_id.empty()) continue;
            if (d.peer_id == self_.peer_id) continue;
            if (!exclude_peer_id.empty() && d.peer_id == exclude_peer_id) continue;
            if (d.peer_id == nh_peer_id) continue;
            c.push_back(d.peer_id);
        }
        if (!c.empty()) {
            std::uniform_int_distribution<size_t> dist(0, c.size() - 1);
            return c[dist(rng_)];
        }
    }

    // Fallback: pick from our active view
    auto act = views_.active_descriptors();
    std::vector<std::string> c;
    for (const auto& d : act) {
        if (d.peer_id == self_.peer_id) continue;
        if (d.peer_id == nh_peer_id) continue;
        if (!exclude_peer_id.empty() && d.peer_id == exclude_peer_id) continue;
        c.push_back(d.peer_id);
    }
    if (c.empty()) return std::nullopt;
    std::uniform_int_distribution<size_t> dist(0, c.size() - 1);
    return c[dist(rng_)];
}

// ------------------- Timers -------------------

void DraughtsNode::tick_keepalive() {
    t_keepalive_.expires_after(std::chrono::milliseconds(cfg_.keepalive_every_ms));
    t_keepalive_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        // send keepalive to active neighbors
        auto act = views_.active_descriptors();
        for (const auto& d : act) {
            auto ep = overlay_endpoint_for(d);
            if (!ep) continue;
            auto m = proto::make_keepalive(rand_u64(), cfg_.lease_ms, self_);
            send_msg(m, *ep);
        }
        // expire local leases
        views_.expire_active(now_ms());
        tick_keepalive();
    });
}

void DraughtsNode::tick_shuffle() {
    t_shuffle_.expires_after(std::chrono::milliseconds(cfg_.shuffle_every_ms));
    t_shuffle_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        if (views_.active_size() > 0) {
            auto act = views_.active_descriptors();
            std::uniform_int_distribution<size_t> dist(0, act.size() - 1);
            auto target = act[dist(rng_)];
            auto ep = overlay_endpoint_for(target);
            if (ep) {
                auto sample = views_.sample_for_shuffle(cfg_.shuffle_k);
                auto m = proto::make_shuffle_req(rand_u64(), sample);
                send_msg(m, *ep);
            }
        }
        tick_shuffle();
    });
}

void DraughtsNode::tick_repair() {
    t_repair_.expires_after(std::chrono::milliseconds(cfg_.repair_every_ms));
    t_repair_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        ensure_active_in_range();
        tick_repair();
    });
}

void DraughtsNode::tick_pending() {
    t_pending_.expires_after(std::chrono::milliseconds(200));
    t_pending_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        uint64_t now = now_ms();
        std::vector<uint64_t> erase;
        for (auto& kv : pending_) {
            auto& p = kv.second;
            if (p.retries >= p.max_retries) {
                erase.push_back(kv.first);
                continue;
            }
            if (now >= p.next_retry_ms) {
                send_msg(p.msg, p.to);
                p.retries++;
                p.next_retry_ms = now + 500;
            }
        }
        for (auto n : erase) pending_.erase(n);
        tick_pending();
    });
}

void DraughtsNode::tick_neighbor_set() {
    t_neighbor_set_.expires_after(std::chrono::milliseconds(cfg_.neighbor_set_every_ms));
    t_neighbor_set_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        // Send our active neighbors to each active neighbor.
        auto act = views_.active_descriptors();
        if (!act.empty()) {
            // Limit neighbor list size
            std::vector<proto::PeerDescriptor> sample;
            for (size_t i = 0; i < act.size() && i < cfg_.neighbor_set_k; ++i) sample.push_back(act[i]);
            for (const auto& d : act) {
                auto ep = overlay_endpoint_for(d);
                if (!ep) continue;
                auto m = proto::make_neighbor_set(rand_u64(), self_, sample);
                send_msg(m, *ep);
            }
        }
        tick_neighbor_set();
    });
}

void DraughtsNode::tick_housekeeping() {
    t_housekeeping_.expires_after(std::chrono::milliseconds(1000));
    t_housekeeping_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        uint64_t now = now_ms();

        if (!cfg_.static_topology) {
            // Prune stale two-hop entries (30s)
            for (auto it = twohop_.begin(); it != twohop_.end(); ) {
                if (now - it->second.updated_ms > 30000) it = twohop_.erase(it);
                else ++it;
            }
        }

        update_active_neighbors_file(false);
        tick_housekeeping();
    });
}

void DraughtsNode::update_active_neighbors_file(bool force) {
    if (cfg_.active_neighbors_file.empty()) return;
    auto act = views_.active_descriptors();

    std::unordered_set<std::string> current;
    current.reserve(act.size());
    for (const auto& d : act) {
        current.insert(d.peer_id + "@" + peer_to_string(d));
    }

    bool changed = (current != active_neighbor_set_);
    if (force || changed) {
        for (const auto& k : current) {
            if (active_neighbor_set_.find(k) == active_neighbor_set_.end()) {
                logger_.info("active neighbor added: " + k);
            }
        }
        for (const auto& k : active_neighbor_set_) {
            if (current.find(k) == current.end()) {
                logger_.info("active neighbor removed: " + k);
            }
        }
        active_neighbor_set_ = std::move(current);
    }

    if (!force && !changed && !neighbors_snapshot_.empty()) return;

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"peer_id\": \"" << json_escape(self_.peer_id) << "\",\n";
    oss << "  \"bind_ip\": \"" << json_escape(cfg_.bind_ip) << "\",\n";
    oss << "  \"overlay_port\": " << self_.overlay_port << ",\n";
    oss << "  \"draughts_port\": " << self_.draughts_port << ",\n";
    oss << "  \"pubkey\": \"" << json_escape(self_.pubkey) << "\",\n";
    oss << "  \"timestamp_ms\": " << now_ms() << ",\n";
    oss << "  \"active_neighbors\": [\n";
    for (size_t i = 0; i < act.size(); ++i) {
        const auto& d = act[i];
        auto ip = addr_from_bytes(d.ip).to_string();
        oss << "    {\n";
        oss << "      \"peer_id\": \"" << json_escape(d.peer_id) << "\",\n";
        oss << "      \"ip\": \"" << json_escape(ip) << "\",\n";
        oss << "      \"overlay_port\": " << d.overlay_port << ",\n";
        oss << "      \"draughts_port\": " << d.draughts_port << ",\n";
        oss << "      \"pubkey\": \"" << json_escape(d.pubkey) << "\"\n";
        oss << "    }";
        if (i + 1 < act.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ]\n";
    oss << "}\n";

    std::string content = oss.str();
    if (!force && content == neighbors_snapshot_) return;

    std::string tmp = cfg_.active_neighbors_file + ".tmp";
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        logger_.warn("failed to open neighbors file: " + cfg_.active_neighbors_file);
        return;
    }
    out << content;
    out.close();
    if (std::rename(tmp.c_str(), cfg_.active_neighbors_file.c_str()) != 0) {
        logger_.warn("failed to rename neighbors file: " + cfg_.active_neighbors_file);
        return;
    }
    neighbors_snapshot_ = std::move(content);
}

void DraughtsNode::remove_active_neighbors_file() {
    if (cfg_.active_neighbors_file.empty()) return;
    std::remove(cfg_.active_neighbors_file.c_str());
    neighbors_snapshot_.clear();
}

void DraughtsNode::write_self_info_file() {
    if (cfg_.self_info_file.empty()) return;
    std::ostringstream oss;
    oss << "peer_id = " << self_.peer_id << "\n";
    oss << "bind_ip = " << cfg_.bind_ip << "\n";
    oss << "overlay_port = " << self_.overlay_port << "\n";
    oss << "draughts_port = " << self_.draughts_port << "\n";
    oss << "pubkey = " << self_.pubkey << "\n";

    std::string tmp = cfg_.self_info_file + ".tmp";
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        logger_.warn("failed to open self info file: " + cfg_.self_info_file);
        return;
    }
    out << oss.str();
    out.close();
    if (std::rename(tmp.c_str(), cfg_.self_info_file.c_str()) != 0) {
        logger_.warn("failed to rename self info file: " + cfg_.self_info_file);
        return;
    }
    logger_.info("published self info: " + cfg_.self_info_file);
}

void DraughtsNode::remove_self_info_file() {
    if (cfg_.static_topology) return;
    if (cfg_.self_info_file.empty()) return;
    std::remove(cfg_.self_info_file.c_str());
}

bool DraughtsNode::load_static_topology() {
    if (cfg_.topology_dir.empty()) {
        logger_.error("static_topology enabled but topology_dir is empty");
        return false;
    }
    if (cfg_.peer_info_dir.empty()) {
        logger_.error("static_topology enabled but peer_info_dir is empty");
        return false;
    }

    const std::string self_neighbors_path = cfg_.topology_dir + "/" + self_.peer_id + ".neighbors";
    auto neighbor_ids = load_neighbors_file(self_neighbors_path);
    if (neighbor_ids.empty()) {
        logger_.warn("no neighbors loaded from " + self_neighbors_path);
    }
    if (neighbor_ids.size() < cfg_.active_min || neighbor_ids.size() > cfg_.active_max) {
        logger_.warn("neighbor degree out of range: " + std::to_string(neighbor_ids.size()) +
                     " (expected " + std::to_string(cfg_.active_min) + "-" + std::to_string(cfg_.active_max) + ")");
    }

    const uint64_t static_lease = std::numeric_limits<uint64_t>::max();
    for (const auto& peer_id : neighbor_ids) {
        if (peer_id == self_.peer_id) continue;
        proto::PeerDescriptor desc;
        if (!load_peer_descriptor(peer_id, cfg_.peer_info_dir, desc)) {
            logger_.warn("failed to load peer info for neighbor: " + peer_id);
            continue;
        }
        views_.upsert_active(desc, static_lease);
        learn_peer(desc);
    }

    for (const auto& neighbor_id : neighbor_ids) {
        std::string path = cfg_.topology_dir + "/" + neighbor_id + ".neighbors";
        auto nnh_ids = load_neighbors_file(path);
        std::vector<proto::PeerDescriptor> nnh_descs;
        nnh_descs.reserve(nnh_ids.size());
        for (const auto& nnh_id : nnh_ids) {
            if (nnh_id == self_.peer_id) continue;
            proto::PeerDescriptor d;
            if (!load_peer_descriptor(nnh_id, cfg_.peer_info_dir, d)) {
                logger_.warn("failed to load peer info for two-hop: " + nnh_id);
                continue;
            }
            nnh_descs.push_back(d);
            learn_peer(d);
        }
        if (!neighbor_id.empty()) {
            twohop_[neighbor_id] = TwoHopEntry{nnh_descs, now_ms()};
        }
    }

    logger_.info("static topology loaded: active=" + std::to_string(views_.active_size()) +
                 " twohop=" + std::to_string(twohop_.size()));
    return true;
}

// ------------------- Overlay logic -------------------

void DraughtsNode::ensure_active_in_range() {
    // If below min, try to activate passive peers.
    while (views_.active_size() < cfg_.active_min) {
        auto pd = views_.pick_passive_random();
        if (!pd) break;
        try_add_active(*pd);
    }

    // If above max, evict random.
    while (views_.active_size() > cfg_.active_max) {
        auto ev = views_.evict_active_random();
        if (!ev) break;
        logger_.info("evict active " + *ev);
    }
}

void DraughtsNode::try_add_active(const proto::PeerDescriptor& d) {
    if (d.peer_id.empty() || d.peer_id == self_.peer_id) return;
    if (views_.active_contains(d.peer_id)) return;
    auto ep = overlay_endpoint_for(d);
    if (!ep) return;

    uint64_t nonce = rand_u64();
    auto msg = proto::make_add_req(nonce, cfg_.lease_ms, self_);
    pending_[nonce] = Pending{msg, *ep, now_ms(), now_ms() + 300, 0, 3};
    send_msg(msg, *ep);
}

std::vector<proto::PeerDescriptor> DraughtsNode::referrals(size_t n) const {
    // Provide referrals from passive view sample.
    auto s = views_.sample_for_shuffle(n);
    return s;
}

// ------------------- Overlay message handlers -------------------

static std::optional<proto::PeerDescriptor> extract_desc_first(const tlv::Bytes& payload) {
    auto items = tlv::parse_all(payload);
    for (auto& it : items) {
        if (it.tag == proto::MsgTag::DESC) {
            try { return proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return std::nullopt; }
        }
    }
    return std::nullopt;
}

void DraughtsNode::handle_join(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    (void)nonce;
    auto d = extract_desc_first(payload);
    if (!d) return;
    learn_peer(*d);

    // If no active neighbors, try to connect directly.
    if (views_.active_size() == 0) {
        try_add_active(*d);
        return;
    }

    // Forward join to a random active neighbor.
    auto next = pick_random_active_except("");
    if (!next) {
        try_add_active(*d);
        return;
    }
    auto ep = overlay_endpoint_for(*next);
    if (!ep) return;

    auto m = proto::make_forward_join(rand_u64(), cfg_.join_ttl, *d);
    send_msg(m, *ep);
    (void)from;
}

void DraughtsNode::handle_forward_join(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    (void)nonce;
    auto items = tlv::parse_all(payload);
    uint16_t ttl = 0;
    std::optional<proto::PeerDescriptor> d;

    for (auto& it : items) {
        if (it.tag == proto::MsgTag::TTL) {
            size_t off = 0;
            ttl = tlv::read_u16(it.value, off);
        } else if (it.tag == proto::MsgTag::DESC) {
            try { d = proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return; }
        }
    }
    if (!d) return;
    learn_peer(*d);

    if (ttl == 0 || views_.active_size() == 0) {
        try_add_active(*d);
        return;
    }

    auto from_id = peer_id_from_endpoint(from).value_or("");
    auto next = pick_random_active_except(from_id);
    if (!next) {
        try_add_active(*d);
        return;
    }
    auto ep = overlay_endpoint_for(*next);
    if (!ep) return;

    auto m = proto::make_forward_join(rand_u64(), static_cast<uint16_t>(ttl - 1), *d);
    send_msg(m, *ep);
}

void DraughtsNode::handle_add_req(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    auto items = tlv::parse_all(payload);
    uint32_t lease_ms = cfg_.lease_ms;
    std::optional<proto::PeerDescriptor> d;

    for (auto& it : items) {
        if (it.tag == proto::MsgTag::LEASE_MS) {
            size_t off = 0;
            lease_ms = tlv::read_u32(it.value, off);
        } else if (it.tag == proto::MsgTag::DESC) {
            try { d = proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return; }
        }
    }
    if (!d) return;
    learn_peer(*d);

    bool accept = views_.active_size() < cfg_.active_max;
    if (accept) {
        views_.upsert_active(*d, now_ms() + lease_ms);
        directory_[d->peer_id] = *d;
        addr_to_peer_id_[overlay_key(addr_from_bytes(d->ip), d->overlay_port)] = d->peer_id;
    }

    auto refs = accept ? std::vector<proto::PeerDescriptor>{} : referrals(3);
    auto ack = proto::make_add_ack(nonce, accept, lease_ms, self_, refs);

    send_msg(ack, from);
}

void DraughtsNode::handle_add_ack(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    // Clear pending
    pending_.erase(nonce);

    auto items = tlv::parse_all(payload);
    bool accept = false;
    uint32_t lease_ms = cfg_.lease_ms;
    std::optional<proto::PeerDescriptor> peer_desc;
    std::vector<proto::PeerDescriptor> refs;

    for (auto& it : items) {
        if (it.tag == proto::MsgTag::ACCEPT) {
            if (!it.value.empty()) accept = (it.value[0] != 0);
        } else if (it.tag == proto::MsgTag::LEASE_MS) {
            size_t off = 0;
            lease_ms = tlv::read_u32(it.value, off);
        } else if (it.tag == proto::MsgTag::DESC) {
            try { peer_desc = proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return; }
        } else if (it.tag == proto::MsgTag::REFERRAL) {
            try { refs.push_back(proto::PeerDescriptor::from_tlv(it.value)); } catch (...) {}
        }
    }
    if (peer_desc) learn_peer(*peer_desc);
    for (const auto& r : refs) learn_peer(r);

    if (accept && peer_desc) {
        views_.upsert_active(*peer_desc, now_ms() + lease_ms);
        directory_[peer_desc->peer_id] = *peer_desc;
        addr_to_peer_id_[overlay_key(addr_from_bytes(peer_desc->ip), peer_desc->overlay_port)] = peer_desc->peer_id;
    }

    (void)from;
}

void DraughtsNode::handle_keepalive(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    (void)nonce;
    auto items = tlv::parse_all(payload);
    uint32_t lease_ms = cfg_.lease_ms;
    std::optional<proto::PeerDescriptor> d;

    for (auto& it : items) {
        if (it.tag == proto::MsgTag::LEASE_MS) {
            size_t off = 0;
            lease_ms = tlv::read_u32(it.value, off);
        } else if (it.tag == proto::MsgTag::DESC) {
            try { d = proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return; }
        }
    }
    if (!d) return;
    learn_peer(*d);

    if (views_.active_contains(d->peer_id)) {
        views_.touch_active(d->peer_id, now_ms() + lease_ms);
    }
    (void)from;
}

void DraughtsNode::handle_shuffle_req(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    // merge sample into passive
    auto items = tlv::parse_all(payload);
    std::vector<proto::PeerDescriptor> sample;
    for (auto& it : items) {
        if (it.tag == proto::MsgTag::DESC) {
            try { sample.push_back(proto::PeerDescriptor::from_tlv(it.value)); } catch (...) {}
        }
    }
    for (const auto& d : sample) learn_peer(d);

    // respond with our sample
    auto resp_sample = views_.sample_for_shuffle(cfg_.shuffle_k);
    auto resp = proto::make_shuffle_resp(nonce, resp_sample);
    send_msg(resp, from);
}

void DraughtsNode::handle_shuffle_resp(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    (void)nonce;
    auto items = tlv::parse_all(payload);
    std::vector<proto::PeerDescriptor> sample;
    for (auto& it : items) {
        if (it.tag == proto::MsgTag::DESC) {
            try { sample.push_back(proto::PeerDescriptor::from_tlv(it.value)); } catch (...) {}
        }
    }
    for (const auto& d : sample) learn_peer(d);
    (void)from;
}

void DraughtsNode::handle_neighbor_set(uint64_t nonce, const tlv::Bytes& payload, const udp::endpoint& from) {
    (void)nonce;
    auto items = tlv::parse_all(payload);
    std::optional<proto::PeerDescriptor> sender;
    std::vector<proto::PeerDescriptor> neighbors;
    for (auto& it : items) {
        if (it.tag == proto::MsgTag::DESC && !sender) {
            try { sender = proto::PeerDescriptor::from_tlv(it.value); } catch (...) { return; }
        } else if (it.tag == proto::MsgTag::NEIGHBOR) {
            try { neighbors.push_back(proto::PeerDescriptor::from_tlv(it.value)); } catch (...) {}
        }
    }
    if (!sender) return;
    learn_peer(*sender);
    for (const auto& d : neighbors) learn_peer(d);

    // Update two-hop cache: sender -> its neighbors
    twohop_[sender->peer_id] = TwoHopEntry{neighbors, now_ms()};

    (void)from;
}
