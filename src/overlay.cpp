#include "overlay.hpp"

#include "util.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>

using boost::asio::ip::address_v4;

namespace {

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

    return BootstrapEntry{addr,
                          static_cast<uint16_t>(overlay_port_i),
                          static_cast<uint16_t>(draughts_port_i)};
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

std::optional<proto::PeerDescriptor> parse_desc(const tlv::Bytes& payload) {
    auto items = tlv::parse_all(payload);
    for (const auto& it : items) {
        if (it.tag == proto::MsgTag::DESC) {
            try {
                return proto::PeerDescriptor::from_tlv(it.value);
            } catch (...) {
                return std::nullopt;
            }
        }
    }
    return std::nullopt;
}

struct ForwardJoinPayload {
    uint16_t ttl = 0;
    proto::PeerDescriptor desc{};
    bool ok = false;
};

ForwardJoinPayload parse_forward_join(const tlv::Bytes& payload) {
    ForwardJoinPayload out{};
    auto items = tlv::parse_all(payload);
    for (const auto& it : items) {
        if (it.tag == proto::MsgTag::TTL) {
            size_t off = 0;
            out.ttl = tlv::read_u16(it.value, off);
        } else if (it.tag == proto::MsgTag::DESC) {
            try {
                out.desc = proto::PeerDescriptor::from_tlv(it.value);
                out.ok = true;
            } catch (...) {
                out.ok = false;
            }
        }
    }
    return out;
}

struct ViewUpdatePayload {
    proto::PeerDescriptor sender{};
    std::vector<proto::PeerDescriptor> neighbors;
    bool ok = false;
};

ViewUpdatePayload parse_view_update(const tlv::Bytes& payload) {
    ViewUpdatePayload out{};
    auto items = tlv::parse_all(payload);
    for (const auto& it : items) {
        if (it.tag == proto::MsgTag::DESC) {
            try {
                out.sender = proto::PeerDescriptor::from_tlv(it.value);
                out.ok = true;
            } catch (...) {
                out.ok = false;
            }
        } else if (it.tag == proto::MsgTag::NEIGHBOR) {
            try {
                out.neighbors.push_back(proto::PeerDescriptor::from_tlv(it.value));
            } catch (...) {}
        }
    }
    return out;
}

} // namespace

HyparviewOverlay::HyparviewOverlay(IoLayer& io,
                                   Config cfg,
                                   proto::PeerDescriptor self,
                                   Logger& logger)
    : io_(io),
      cfg_(std::move(cfg)),
      self_(std::move(self)),
      logger_(logger),
      views_(cfg_.passive_max, cfg_.active_max),
      t_ping_(io_.context()),
      t_neighbor_check_(io_.context()),
      t_view_update_(io_.context()),
      t_directory_(io_.context()) {}

bool HyparviewOverlay::start() {
    auto overlay_ep = io_.overlay_local_endpoint();
    auto draughts_ep = io_.draughts_local_endpoint();
    if (overlay_ep.address().is_v4()) {
        self_.ip = bytes_from_addr(overlay_ep.address().to_v4());
        self_.overlay_port = overlay_ep.port();
    }
    if (draughts_ep.address().is_v4()) {
        self_.draughts_port = draughts_ep.port();
    }

    logger_.info("overlay start peer_id=" + self_.peer_id + " bind=" + peer_to_string(self_));
    write_self_info_file();
    update_active_neighbors_file(true);

    if (!cfg_.is_bootstrap) {
        for (const auto& b : cfg_.bootstrap_endpoints) {
            auto be = parse_bootstrap(b);
            if (!be) {
                logger_.warn("invalid bootstrap: " + b);
                continue;
            }
            proto::Message m = proto::make_join(rand_u64(), self_);
            io_.send_overlay(proto::encode(m), udp::endpoint(be->addr, be->overlay_port));
        }
    }

    tick_ping();
    tick_neighbor_check();
    tick_view_update();
    tick_directory_scan();
    return true;
}

void HyparviewOverlay::stop() {
    t_ping_.cancel();
    t_neighbor_check_.cancel();
    t_view_update_.cancel();
    t_directory_.cancel();
    remove_active_neighbors_file();
    remove_self_info_file();
}

void HyparviewOverlay::on_datagram(const tlv::Bytes& bytes, const udp::endpoint& from) {
    proto::Message m;
    try {
        m = proto::decode(bytes);
    } catch (const std::exception& e) {
        logger_.warn(std::string("overlay decode failed from ") + from.address().to_string() +
                     ":" + std::to_string(from.port()) + ": " + e.what());
        return;
    }

    switch (m.type) {
        case proto::MsgType::JOIN: handle_join(m.payload, from); break;
        case proto::MsgType::FORWARD_JOIN: handle_forward_join(m.payload, from); break;
        case proto::MsgType::JOIN_ACCEPT: handle_join_accept(m.payload, from); break;
        case proto::MsgType::PING: handle_ping(m.payload, from); break;
        case proto::MsgType::PONG: handle_pong(m.payload, from); break;
        case proto::MsgType::VIEW_UPDATE: handle_view_update(m.payload, from); break;
        case proto::MsgType::VIEW_UPDATE_REQ: handle_view_update_req(m.payload, from); break;
        default: break;
    }
}

HyparviewOverlay::Status HyparviewOverlay::status() const {
    Status s{};
    s.self = self_;
    s.active = views_.active_size();
    s.passive = views_.passive_size();
    s.directory = directory_.size();
    return s;
}

proto::PeerDescriptor HyparviewOverlay::self_descriptor() const {
    return self_;
}

std::vector<proto::PeerDescriptor> HyparviewOverlay::active_neighbors() const {
    return views_.active_descriptors();
}

std::vector<HyparviewOverlay::TwoHopEntry> HyparviewOverlay::twohop_snapshot() const {
    std::vector<TwoHopEntry> out;
    out.reserve(twohop_.size());
    for (const auto& kv : twohop_) {
        TwoHopEntry e{};
        e.via_peer_id = kv.first;
        e.neighbors = kv.second.neighbors;
        e.expires_at_ms = kv.second.expires_at_ms;
        e.stale_rounds = kv.second.stale_rounds;
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<proto::PeerDescriptor> HyparviewOverlay::directory_snapshot(size_t limit) const {
    std::vector<proto::PeerDescriptor> out;
    out.reserve(directory_.size());
    uint64_t now = now_ms();
    for (const auto& kv : directory_) {
        if (kv.first == self_.peer_id) continue;
        if (now >= kv.second.expires_at_ms) continue;
        out.push_back(kv.second.desc);
        if (limit > 0 && out.size() >= limit) break;
    }
    return out;
}

size_t HyparviewOverlay::directory_size() const {
    uint64_t now = now_ms();
    size_t count = 0;
    for (const auto& kv : directory_) {
        if (kv.first == self_.peer_id) continue;
        if (now >= kv.second.expires_at_ms) continue;
        ++count;
    }
    return count;
}

std::optional<proto::PeerDescriptor> HyparviewOverlay::lookup_peer(const std::string& peer_id) const {
    if (peer_id == self_.peer_id) return self_;
    auto it = directory_.find(peer_id);
    if (it == directory_.end()) return std::nullopt;
    if (now_ms() >= it->second.expires_at_ms) return std::nullopt;
    return it->second.desc;
}

std::optional<proto::PeerDescriptor> HyparviewOverlay::lookup_peer_by_draughts_endpoint(
    const address_v4& addr, uint16_t port) const {
    if (port == 0) return std::nullopt;
    auto it = draughts_addr_to_peer_id_.find(draughts_key(addr, port));
    if (it == draughts_addr_to_peer_id_.end()) return std::nullopt;
    return lookup_peer(it->second);
}

std::optional<proto::PeerDescriptor> HyparviewOverlay::pick_random_active_except(
    const std::string& exclude_peer_id) const {
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

std::optional<std::string> HyparviewOverlay::pick_nnh_for(const std::string& nh_peer_id,
                                                          const std::string& exclude_peer_id) const {
    uint64_t now = now_ms();
    auto it = twohop_.find(nh_peer_id);
    if (it != twohop_.end()) {
        std::vector<std::string> c;
        for (const auto& n : it->second.neighbors) {
            if (n.expires_at_ms <= now) continue;
            const auto& d = n.desc;
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

void HyparviewOverlay::handle_join(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto d = parse_desc(payload);
    if (!d) return;
    if (d->peer_id == self_.peer_id) return;

    learn_peer(*d, &from);

    if (views_.active_contains(d->peer_id)) {
        views_.upsert_active(*d, now_ms());
        return;
    }

    size_t cur = views_.active_size();
    bool accept = false;
    if (cur < cfg_.active_min) accept = true;
    else if (cur > cfg_.active_max) accept = false;
    else {
        std::uniform_int_distribution<int> dist(0, 1);
        accept = (dist(rng_) == 0);
    }

    if (accept) {
        accept_joiner(*d, from);
        return;
    }

    views_.insert_passive(*d);

    uint16_t ttl = cfg_.join_ttl;
    if (ttl == 0 || views_.active_size() == 0) {
        accept_joiner(*d, from);
        return;
    }

    auto from_peer = peer_id_from_endpoint(from).value_or("");
    forward_join(*d, ttl, from_peer);
}

void HyparviewOverlay::handle_forward_join(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto parsed = parse_forward_join(payload);
    if (!parsed.ok) return;
    if (parsed.desc.peer_id == self_.peer_id) return;

    learn_peer(parsed.desc, &from);

    if (views_.active_contains(parsed.desc.peer_id)) {
        views_.upsert_active(parsed.desc, now_ms());
        return;
    }

    uint16_t ttl = parsed.ttl;
    if (ttl == 0 || views_.active_size() == 0) {
        accept_joiner(parsed.desc, from);
        return;
    }

    size_t cur = views_.active_size();
    bool accept = false;
    if (cur < cfg_.active_min) accept = true;
    else if (cur > cfg_.active_max) accept = false;
    else {
        std::uniform_int_distribution<int> dist(0, 1);
        accept = (dist(rng_) == 0);
    }
    if (accept) {
        accept_joiner(parsed.desc, from);
        return;
    }

    views_.insert_passive(parsed.desc);
    auto from_peer = peer_id_from_endpoint(from).value_or("");
    forward_join(parsed.desc, ttl, from_peer);
}

void HyparviewOverlay::handle_join_accept(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto d = parse_desc(payload);
    if (!d) return;
    if (d->peer_id == self_.peer_id) return;
    learn_peer(*d, &from);

    uint64_t now = now_ms();
    views_.upsert_active(*d, now);
    update_active_neighbors_file(false);
}

void HyparviewOverlay::handle_ping(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto d = parse_desc(payload);
    if (!d) return;
    if (d->peer_id == self_.peer_id) return;
    learn_peer(*d, &from);

    uint64_t now = now_ms();
    if (views_.active_contains(d->peer_id)) {
        views_.upsert_active(*d, now);
    } else {
        views_.insert_passive(*d);
    }

    proto::Message m = proto::make_pong(rand_u64(), self_);
    io_.send_overlay(proto::encode(m), from);
}

void HyparviewOverlay::handle_pong(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto d = parse_desc(payload);
    if (!d) return;
    if (d->peer_id == self_.peer_id) return;
    learn_peer(*d, &from);

    uint64_t now = now_ms();
    if (views_.active_contains(d->peer_id)) {
        views_.upsert_active(*d, now);
    } else {
        views_.insert_passive(*d);
    }
}

void HyparviewOverlay::handle_view_update(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto parsed = parse_view_update(payload);
    if (!parsed.ok) return;
    if (parsed.sender.peer_id == self_.peer_id) return;

    uint64_t now = now_ms();
    uint64_t valid_ms = static_cast<uint64_t>(cfg_.valid_window_s) * 1000;

    learn_peer(parsed.sender, &from);
    if (views_.active_contains(parsed.sender.peer_id)) {
        views_.upsert_active(parsed.sender, now);
    }

    TwoHopRec rec{};
    rec.expires_at_ms = now + valid_ms;
    rec.stale_rounds = 0;
    for (const auto& d : parsed.neighbors) {
        if (d.peer_id == self_.peer_id) continue;
        learn_peer(d, nullptr);
        rec.neighbors.push_back(TwoHopNeighbor{d, now + valid_ms});
    }
    twohop_[parsed.sender.peer_id] = std::move(rec);
}

void HyparviewOverlay::handle_view_update_req(const tlv::Bytes& payload, const udp::endpoint& from) {
    auto d = parse_desc(payload);
    if (!d) return;
    if (d->peer_id == self_.peer_id) return;
    learn_peer(*d, &from);
    proto::Message m = proto::make_view_update(rand_u64(), self_, views_.active_descriptors());
    io_.send_overlay(proto::encode(m), from);
}

void HyparviewOverlay::tick_ping() {
    t_ping_.expires_after(std::chrono::milliseconds(cfg_.ping_interval_ms));
    t_ping_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        uint64_t now = now_ms();

        auto act = views_.active_descriptors();
        for (const auto& d : act) {
            send_ping_to(d);
        }

        auto expired = views_.expire_active(now, cfg_.peer_timeout_ms);
        for (const auto& d : expired) {
            logger_.info("active timeout: " + d.peer_id);
            views_.insert_passive(d);
        }

        tick_ping();
    });
}

void HyparviewOverlay::tick_neighbor_check() {
    t_neighbor_check_.expires_after(std::chrono::milliseconds(cfg_.ping_interval_ms));
    t_neighbor_check_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        ensure_active_in_range();
        tick_neighbor_check();
    });
}

void HyparviewOverlay::tick_view_update() {
    t_view_update_.expires_after(std::chrono::milliseconds(cfg_.view_update_interval_ms));
    t_view_update_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        auto act = views_.active_descriptors();
        for (const auto& d : act) {
            send_view_update_to(d);
        }
        update_active_neighbors_file(false);
        tick_view_update();
    });
}

void HyparviewOverlay::tick_directory_scan() {
    uint64_t interval_ms = static_cast<uint64_t>(cfg_.valid_window_s) * 500;
    if (interval_ms < 1000) interval_ms = 1000;
    t_directory_.expires_after(std::chrono::milliseconds(interval_ms));
    t_directory_.async_wait([this](boost::system::error_code ec) {
        if (ec) return;
        uint64_t now = now_ms();
        expire_directory(now);
        expire_twohop(now);
        tick_directory_scan();
    });
}

void HyparviewOverlay::ensure_active_in_range() {
    if (views_.active_size() < cfg_.active_min) {
        auto pd = views_.pick_passive_random();
        if (pd) {
            auto fresh = lookup_peer(pd->peer_id);
            if (fresh) {
                send_join(*fresh);
            }
        }
    }

    while (views_.active_size() > cfg_.active_max) {
        auto ev = views_.evict_active_random();
        if (!ev) break;
        logger_.info("evict active " + ev->peer_id);
        views_.insert_passive(*ev);
    }
}

void HyparviewOverlay::accept_joiner(const proto::PeerDescriptor& d, const udp::endpoint& from) {
    uint64_t now = now_ms();
    views_.upsert_active(d, now);
    update_active_neighbors_file(false);

    proto::Message m = proto::make_join_accept(rand_u64(), self_);
    io_.send_overlay(proto::encode(m), from);
}

void HyparviewOverlay::forward_join(const proto::PeerDescriptor& d, uint16_t ttl, const std::string& from_peer) {
    if (ttl == 0 || views_.active_size() == 0) return;
    uint16_t next_ttl = static_cast<uint16_t>(ttl - 1);
    auto next = pick_random_active_except(from_peer);
    if (!next) {
        next = pick_random_active_except("");
    }
    if (!next) return;
    auto ep = overlay_endpoint_for(*next);
    if (!ep) return;
    proto::Message m = proto::make_forward_join(rand_u64(), next_ttl, d);
    io_.send_overlay(proto::encode(m), *ep);
}

void HyparviewOverlay::send_join(const proto::PeerDescriptor& target) {
    auto ep = overlay_endpoint_for(target);
    if (!ep) return;
    proto::Message m = proto::make_join(rand_u64(), self_);
    io_.send_overlay(proto::encode(m), *ep);
}

void HyparviewOverlay::send_view_update_to(const proto::PeerDescriptor& target) {
    auto ep = overlay_endpoint_for(target);
    if (!ep) return;

    auto neighbors = views_.active_descriptors();
    neighbors.erase(std::remove_if(neighbors.begin(), neighbors.end(),
                                   [&](const proto::PeerDescriptor& d) {
                                       return d.peer_id == target.peer_id;
                                   }),
                    neighbors.end());
    proto::Message m = proto::make_view_update(rand_u64(), self_, neighbors);
    io_.send_overlay(proto::encode(m), *ep);
}

void HyparviewOverlay::send_view_update_req(const proto::PeerDescriptor& target) {
    auto ep = overlay_endpoint_for(target);
    if (!ep) return;
    proto::Message m = proto::make_view_update_req(rand_u64(), self_);
    io_.send_overlay(proto::encode(m), *ep);
}

void HyparviewOverlay::send_ping_to(const proto::PeerDescriptor& target) {
    auto ep = overlay_endpoint_for(target);
    if (!ep) return;
    proto::Message m = proto::make_ping(rand_u64(), self_);
    io_.send_overlay(proto::encode(m), *ep);
}

void HyparviewOverlay::learn_peer(const proto::PeerDescriptor& d, const udp::endpoint* from) {
    if (d.peer_id.empty()) return;
    if (d.peer_id == self_.peer_id) return;

    uint64_t now = now_ms();
    uint64_t valid_ms = static_cast<uint64_t>(cfg_.valid_window_s) * 1000;

    auto& entry = directory_[d.peer_id];
    entry.desc = d;
    entry.expires_at_ms = now + valid_ms;
    entry.stale_rounds = 0;

    overlay_addr_to_peer_id_[overlay_key(addr_from_bytes(d.ip), d.overlay_port)] = d.peer_id;
    if (from) {
        overlay_addr_to_peer_id_[overlay_key(from->address().to_v4(), from->port())] = d.peer_id;
    }
    if (d.draughts_port != 0) {
        draughts_addr_to_peer_id_[draughts_key(addr_from_bytes(d.ip), d.draughts_port)] = d.peer_id;
    }
    views_.insert_passive(d);
}

void HyparviewOverlay::expire_directory(uint64_t now) {
    std::vector<std::string> to_remove;
    for (auto& kv : directory_) {
        if (kv.first == self_.peer_id) continue;
        if (now < kv.second.expires_at_ms) continue;
        kv.second.stale_rounds++;
        if (kv.second.stale_rounds >= 3) {
            to_remove.push_back(kv.first);
            continue;
        }
        send_ping_to(kv.second.desc);
    }
    for (const auto& id : to_remove) {
        auto it = directory_.find(id);
        if (it == directory_.end()) continue;
        auto addr = addr_from_bytes(it->second.desc.ip);
        overlay_addr_to_peer_id_.erase(overlay_key(addr, it->second.desc.overlay_port));
        draughts_addr_to_peer_id_.erase(draughts_key(addr, it->second.desc.draughts_port));
        directory_.erase(it);
    }
}

void HyparviewOverlay::expire_twohop(uint64_t now) {
    std::vector<std::string> to_remove;
    for (auto& kv : twohop_) {
        if (now < kv.second.expires_at_ms) continue;
        kv.second.stale_rounds++;
        if (kv.second.stale_rounds >= 3) {
            to_remove.push_back(kv.first);
            continue;
        }
        auto active = views_.get_active(kv.first);
        if (active) {
            send_view_update_req(*active);
        }
    }
    for (const auto& id : to_remove) {
        twohop_.erase(id);
    }
}

std::optional<std::string> HyparviewOverlay::peer_id_from_endpoint(const udp::endpoint& ep) const {
    auto it = overlay_addr_to_peer_id_.find(overlay_key(ep.address().to_v4(), ep.port()));
    if (it == overlay_addr_to_peer_id_.end()) return std::nullopt;
    return it->second;
}

std::optional<HyparviewOverlay::udp::endpoint> HyparviewOverlay::overlay_endpoint_for(
    const proto::PeerDescriptor& d) const {
    if (d.overlay_port == 0) return std::nullopt;
    return udp::endpoint(addr_from_bytes(d.ip), d.overlay_port);
}

void HyparviewOverlay::update_active_neighbors_file(bool force) {
    if (cfg_.active_neighbors_file.empty()) return;
    auto act = views_.active_descriptors();

    std::unordered_set<std::string> current;
    for (const auto& d : act) {
        current.insert(d.peer_id);
    }

    bool changed = (current != active_neighbor_set_);
    if (changed) {
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
    if (!force && !changed && content == neighbors_snapshot_) return;

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

void HyparviewOverlay::remove_active_neighbors_file() {
    if (cfg_.active_neighbors_file.empty()) return;
    std::remove(cfg_.active_neighbors_file.c_str());
    neighbors_snapshot_.clear();
}

void HyparviewOverlay::write_self_info_file() {
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

void HyparviewOverlay::remove_self_info_file() {
    if (cfg_.self_info_file.empty()) return;
    std::remove(cfg_.self_info_file.c_str());
}
