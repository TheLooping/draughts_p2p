#include "node.hpp"

#include "util.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
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

std::string draughts_key(const address_v4& addr, uint16_t port) {
    return addr.to_string() + ":" + std::to_string(port);
}

std::string peer_to_string(const proto::PeerDescriptor& d) {
    auto addr = addr_from_bytes(d.ip);
    std::ostringstream oss;
    oss << addr.to_string() << ":" << d.overlay_port << ":" << d.draughts_port;
    return oss.str();
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
      t_housekeeping_(io_) {
}

bool DraughtsNode::start() {
    auto addr = make_address_v4(cfg_.bind_ip);
    self_.ip = bytes_from_addr(addr);
    self_.overlay_port = cfg_.overlay_port;
    self_.draughts_port = cfg_.draughts_port;

    logger_.info("node start peer_id=" + self_.peer_id + " bind=" + peer_to_string(self_));

    write_self_info_file();
    if (!load_static_topology()) return false;
    update_active_neighbors_file(true);
    tick_housekeeping();
    return true;
}

void DraughtsNode::stop() {
    logger_.info("stop requested");
    remove_self_info_file();
    remove_active_neighbors_file();
    t_housekeeping_.cancel();
    io_.stop();
}

void DraughtsNode::cmd_show_id() {
    std::ostringstream oss;
    oss << "peer_id=" << self_.peer_id << " bind=" << peer_to_string(self_)
        << " active=" << active_neighbors_.size() << "/" << cfg_.active_max;
    console_.println(oss.str());
    logger_.info("cli id");
}

void DraughtsNode::cmd_show_neighbors() {
    const auto& act = active_neighbors_;
    std::ostringstream oss;
    oss << "Active neighbors (" << act.size() << "):";
    console_.println(oss.str());
    if (act.empty()) {
        console_.println("  (none)");
        logger_.info("cli neighbors count=0");
        return;
    }
    for (const auto& d : act) {
        console_.println("  - " + d.peer_id + " @ " + peer_to_string(d));
    }
    logger_.info("cli neighbors count=" + std::to_string(act.size()));
}

void DraughtsNode::cmd_show_twohop() {
    console_.println("Two-hop cache entries: " + std::to_string(twohop_.size()));
    if (twohop_.empty()) {
        console_.println("  (empty)");
        logger_.info("cli twohop entries=0");
        return;
    }
    for (const auto& kv : twohop_) {
        const auto& peer = kv.first;
        const auto& e = kv.second;
        std::ostringstream oss;
        oss << "  * " << peer << " (" << e.neighbors.size() << "):";
        console_.println(oss.str());
        if (e.neighbors.empty()) {
            console_.println("    (none)");
            continue;
        }
        std::ostringstream line;
        line << "    ";
        for (size_t i = 0; i < e.neighbors.size(); ++i) {
            if (i > 0) line << ", ";
            line << e.neighbors[i].peer_id;
        }
        console_.println(line.str());
    }
    logger_.info("cli twohop entries=" + std::to_string(twohop_.size()));
}

void DraughtsNode::cmd_show_peers() {
    console_.println("Known peers (directory): " + std::to_string(directory_.size()));
    if (directory_.empty()) {
        console_.println("  (empty)");
        logger_.info("cli peers count=0");
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
    logger_.info("cli peers count=" + std::to_string(directory_.size()));
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
    return active_neighbors_;
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

// ------------------- Helpers -------------------

void DraughtsNode::learn_peer(const proto::PeerDescriptor& d) {
    if (d.peer_id.empty()) return;
    if (d.peer_id == self_.peer_id) return;
    directory_[d.peer_id] = d;
    if (d.draughts_port != 0) {
        draughts_addr_to_peer_id_[draughts_key(addr_from_bytes(d.ip), d.draughts_port)] = d.peer_id;
    }
}

std::optional<proto::PeerDescriptor> DraughtsNode::pick_random_active_except(const std::string& exclude_peer_id) const {
    if (active_neighbors_.empty()) return std::nullopt;
    std::vector<proto::PeerDescriptor> candidates;
    candidates.reserve(active_neighbors_.size());
    for (const auto& d : active_neighbors_) {
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
    std::vector<std::string> c;
    for (const auto& d : active_neighbors_) {
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

void DraughtsNode::tick_housekeeping() {
    t_housekeeping_.expires_after(std::chrono::milliseconds(1000));
    t_housekeeping_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        update_active_neighbors_file(false);
        tick_housekeeping();
    });
}

void DraughtsNode::update_active_neighbors_file(bool force) {
    if (cfg_.active_neighbors_file.empty()) return;
    const auto& act = active_neighbors_;

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
    if (cfg_.self_info_file.empty()) return;
}

bool DraughtsNode::load_static_topology() {
    if (cfg_.topology_dir.empty()) {
        logger_.error("topology_dir is empty");
        return false;
    }
    if (cfg_.peer_info_dir.empty()) {
        logger_.error("peer_info_dir is empty");
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

    active_neighbors_.clear();
    std::unordered_set<std::string> seen;
    for (const auto& peer_id : neighbor_ids) {
        if (peer_id == self_.peer_id) continue;
        if (!seen.insert(peer_id).second) continue;
        proto::PeerDescriptor desc;
        if (!load_peer_descriptor(peer_id, cfg_.peer_info_dir, desc)) {
            logger_.warn("failed to load peer info for neighbor: " + peer_id);
            continue;
        }
        active_neighbors_.push_back(desc);
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
            twohop_[neighbor_id] = TwoHopEntry{nnh_descs};
        }
    }

    logger_.info("static topology loaded: active=" + std::to_string(active_neighbors_.size()) +
                 " twohop=" + std::to_string(twohop_.size()));
    return true;
}
