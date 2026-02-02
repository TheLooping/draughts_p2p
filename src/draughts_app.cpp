#include "draughts_app.hpp"

#include "base64.hpp"
#include "cipher.hpp"
#include "util.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <sstream>

#include <openssl/sha.h>
#include <unistd.h>

using boost::asio::ip::address_v4;

namespace {

bool approx_eq(double a, double b) {
    return std::fabs(a - b) < 1e-9;
}

address_v4 addr_from_bytes(const std::array<std::uint8_t, 4>& b) {
    address_v4::bytes_type bytes{};
    std::copy(b.begin(), b.end(), bytes.begin());
    return address_v4(bytes);
}

bool is_zero_pk_bytes(const std::uint8_t pk[draughts::kPkSize]) {
    for (size_t i = 0; i < draughts::kPkSize; ++i) {
        if (pk[i] != 0) return false;
    }
    return true;
}

bool transform_addr_layer(std::uint8_t addr[draughts::kAddrSize],
                          const draughts::crypto::Sm2KeyPair& self_key,
                          const draughts::crypto::PubKey& peer_pub) {
    auto secret = self_key.DeriveSharedSecret(peer_pub);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    crypto::CommutativeCipher::TransformInPlace(addr, draughts::kAddrSize, key_iv.first, key_iv.second);
    return true;
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

} // namespace

DraughtsApp::ResponderLru::ResponderLru(size_t capacity) : capacity_(capacity) {}

void DraughtsApp::ResponderLru::insert_head(const std::string& sid, const ResponderValue& value) {
    lru_.push_front(Entry{sid, value});
    index_[sid].push_front(lru_.begin());
    evict_if_needed();
}

bool DraughtsApp::ResponderLru::get_first_and_move_to_tail(const std::string& sid, ResponderValue& out) {
    auto it = index_.find(sid);
    if (it == index_.end() || it->second.empty()) return false;
    auto list_it = it->second.front();
    out = list_it->value;
    lru_.splice(lru_.end(), lru_, list_it);
    it->second.pop_front();
    it->second.push_back(std::prev(lru_.end()));
    return true;
}

size_t DraughtsApp::ResponderLru::size() const {
    return lru_.size();
}

size_t DraughtsApp::ResponderLru::capacity() const {
    return capacity_;
}

std::vector<std::pair<std::string, size_t>> DraughtsApp::ResponderLru::session_counts() const {
    std::vector<std::pair<std::string, size_t>> out;
    out.reserve(index_.size());
    for (const auto& kv : index_) {
        out.emplace_back(kv.first, kv.second.size());
    }
    return out;
}

void DraughtsApp::ResponderLru::evict_if_needed() {
    if (capacity_ == 0) {
        lru_.clear();
        index_.clear();
        return;
    }
    while (lru_.size() > capacity_) {
        auto it = std::prev(lru_.end());
        auto sid = it->sid;
        auto idx = index_.find(sid);
        if (idx != index_.end() && !idx->second.empty()) {
            idx->second.pop_back();
            if (idx->second.empty()) index_.erase(idx);
        }
        lru_.erase(it);
    }
}

DraughtsApp::DraughtsApp(boost::asio::io_context& io,
                         Config cfg,
                         DraughtsNode& node,
                         draughts::crypto::Sm2KeyPair identity,
                         Logger& logger,
                         Console& console)
    : io_(io),
      cfg_(std::move(cfg)),
      node_(node),
      identity_(std::move(identity)),
      logger_(logger),
      console_(console),
      sock_(io_),
      responder_lru_(kResponderLruCapacity),
      t_housekeeping_(io_) {
    ciplc_.a = cfg_.ciplc_a;
    ciplc_.b = cfg_.ciplc_b;
    ciplc_.c = cfg_.ciplc_c;
    ciplc_.epsilon = cfg_.ciplc_epsilon;
    ciplc_.x = cfg_.ciplc_x0;
}

bool DraughtsApp::start() {
    udp::endpoint bind_ep(address_v4::from_string(cfg_.bind_ip), cfg_.draughts_port);
    boost::system::error_code ec;
    sock_.open(udp::v4(), ec);
    if (ec) {
        logger_.error("failed to open draughts socket: " + ec.message());
        return false;
    }
    sock_.bind(bind_ep, ec);
    if (ec) {
        logger_.error("failed to bind draughts socket: " + ec.message() +
                      " (addr=" + cfg_.bind_ip + ":" + std::to_string(cfg_.draughts_port) + ")");
        return false;
    }

    init_trace();
    do_receive();

    auto tick = std::make_shared<std::function<void()>>();
    *tick = [this, tick]() {
        t_housekeeping_.expires_after(std::chrono::milliseconds(1000));
        t_housekeeping_.async_wait([this, tick](boost::system::error_code ec) {
            if (ec) return;
            prune_sessions();
            (*tick)();
        });
    };
    (*tick)();
    return true;
}

void DraughtsApp::stop() {
    boost::system::error_code ec;
    sock_.close(ec);
    t_housekeeping_.cancel();
}

void DraughtsApp::cmd_send(const std::string& dest, const std::string& text) {
    if (dest.empty() || text.empty()) {
        console_.println("usage: send <peer_id|ipv4:port> <text>");
        return;
    }
    logger_.info("cli send dest=" + dest + " text_len=" + std::to_string(text.size()));

    address_v4 resp_addr;
    uint16_t resp_port = 0;
    draughts::crypto::PubKey resp_pub{};
    std::string resp_peer_id;
    if (!resolve_peer_target(dest, resp_addr, resp_port, resp_pub, resp_peer_id)) {
        console_.println("responder not found (need peer_id or ipv4:port with published info)");
        logger_.warn("cli send failed: responder not found dest=" + dest);
        return;
    }

    address_v4 nh_addr;
    uint16_t nh_port = 0;
    draughts::crypto::PubKey nh_pub{};
    address_v4 nnh_addr;
    uint16_t nnh_port = 0;
    draughts::crypto::PubKey nnh_pub{};
    if (!pick_nh_nnh(nh_addr, nh_port, nh_pub, nnh_addr, nnh_port, nnh_pub, "")) {
        console_.println("no active neighbors to start random walk");
        logger_.warn("cli send failed: no active neighbors");
        return;
    }
    std::string nh_peer_id;
    if (auto nh_desc = node_.lookup_peer_by_draughts_endpoint(nh_addr, nh_port)) {
        nh_peer_id = nh_desc->peer_id;
    }
    std::string nnh_peer_id;
    if (auto nnh_desc = node_.lookup_peer_by_draughts_endpoint(nnh_addr, nnh_port)) {
        nnh_peer_id = nnh_desc->peer_id;
    }

    draughts::DraughtsPacket p{};

    // Session ID
    random_session_id(p.session_id);
    std::string sid = session_id_from_bytes(p.session_id);

    // Per-hop key for the first hop (also seeds c_addr_real_receiver layers).
    draughts::crypto::Sm2KeyPair ph_tmp;
    auto ph_pub = ph_tmp.public_key_raw();
    std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);
    std::memcpy(p.params.pk_pph_tmp, ph_pub.data(), draughts::kPkSize);

    // End-to-end init key (per-session) for initiator address + payload.
    draughts::crypto::Sm2KeyPair init_tmp;
    auto init_pub = init_tmp.public_key_raw();
    std::memcpy(p.params.pk_init_tmp, init_pub.data(), draughts::kPkSize);

    // Addresses
    addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
    addr_to_bytes(resp_addr, resp_port, p.params.c_addr_real_receiver);
    addr_to_bytes(address_v4::from_string(cfg_.bind_ip), cfg_.draughts_port, p.params.c_addr_real_sender);

    // Layering rules for c_addr_real_receiver / c_addr_real_sender.
    if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nh_pub,
                             "request_init_add_nh", "request", "c_addr_real_receiver",
                             "encrypt",
                             "ph_tmp_priv", "nh_pub",
                             nh_peer_id,
                             peer_label_for(nh_addr, nh_port),
                             sid)) {
        console_.println("failed to wrap c_addr_real_receiver for first hop");
        logger_.warn("cli send failed: wrap c_addr_real_receiver (nh)");
        return;
    }
    if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nnh_pub,
                             "request_init_add_nnh", "request", "c_addr_real_receiver",
                             "encrypt",
                             "ph_tmp_priv", "nnh_pub",
                             nnh_peer_id,
                             peer_label_for(nnh_addr, nnh_port),
                             sid)) {
        console_.println("failed to wrap c_addr_real_receiver for second hop");
        logger_.warn("cli send failed: wrap c_addr_real_receiver (nnh)");
        return;
    }
    if (!transform_real_addr(p.params.c_addr_real_sender, init_tmp, resp_pub,
                             "init_encrypt", "request", "c_addr_real_sender",
                             "encrypt",
                             "init_tmp_priv", "responder_pub",
                             resp_peer_id,
                             peer_label_for(resp_addr, resp_port),
                             sid)) {
        console_.println("failed to wrap c_addr_real_sender for responder");
        logger_.warn("cli send failed: wrap c_addr_real_sender");
        return;
    }

    p.params.x = cfg_.ciplc_x0;
    p.params.magic_num = cfg_.magic_num;

    // Encrypt payload
    std::uint8_t pt[draughts::kDataSize] = {};
    encode_payload(text, pt);

    auto secret = init_tmp.DeriveSharedSecret(resp_pub);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    std::memcpy(p.c_data, pt, draughts::kDataSize);
    crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);

    if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
        console_.println("failed to encrypt params for first hop");
        logger_.warn("cli send failed: encrypt params");
        return;
    }

    initiator_session_ids_.insert(sid);
    initiator_sessions_.emplace(sid, InitiatorSession{std::move(init_tmp), resp_pub, now_ms()});

    logger_.info("cli send request session=" + session_hex(sid) +
                 " responder=" + endpoint_to_string(resp_addr, resp_port) +
                 " nh=" + endpoint_to_string(nh_addr, nh_port) +
                 " nnh=" + endpoint_to_string(nnh_addr, nnh_port));

    if (!send_packet_to(p, nh_addr, nh_port)) {
        console_.println("failed to send packet to next hop");
        logger_.warn("cli send failed session=" + session_hex(sid));
        initiator_session_ids_.erase(sid);
        initiator_sessions_.erase(sid);
        return;
    }

    console_.println("sent session=" + session_hex(sid) + " to responder=" + endpoint_to_string(resp_addr, resp_port));
}

void DraughtsApp::cmd_inbox() {
    console_.println("Inbox messages: " + std::to_string(inbox_.size()));
    for (const auto& item : inbox_) {
        std::ostringstream oss;
        if (item.is_reply) {
            oss << "  [REPLY] session=" << item.session_hex << " text=\"" << item.text << "\"";
        } else {
            oss << "  [REQUEST] session=" << item.session_hex << " from=" << item.from_addr
                << " text=\"" << item.text << "\"";
        }
        console_.println(oss.str());
    }
    logger_.info("cli inbox count=" + std::to_string(inbox_.size()));
}

void DraughtsApp::cmd_requests() {
    auto counts = responder_lru_.session_counts();
    console_.println("Pending responder sessions: " + std::to_string(counts.size())
                     + " (entries=" + std::to_string(responder_lru_.size()) + ")");
    for (const auto& kv : counts) {
        console_.println("  session=" + session_hex(kv.first) + " pending=" + std::to_string(kv.second));
    }
    logger_.info("cli requests sessions=" + std::to_string(counts.size()) +
                 " entries=" + std::to_string(responder_lru_.size()));
}

void DraughtsApp::cmd_reply(const std::string& session_hex_in, const std::string& text) {
    if (session_hex_in.empty() || text.empty()) {
        console_.println("usage: reply <session_hex> <text>");
        return;
    }
    logger_.info("cli reply session=" + session_hex_in + " text_len=" + std::to_string(text.size()));

    std::string sid;
    if (session_hex_in.size() % 2 != 0) {
        console_.println("session_hex must have even length");
        logger_.warn("cli reply failed: invalid session_hex length");
        return;
    }
    sid.resize(session_hex_in.size() / 2);
    try {
        for (size_t i = 0; i < session_hex_in.size(); i += 2) {
            auto byte = std::stoi(session_hex_in.substr(i, 2), nullptr, 16);
            sid[i / 2] = static_cast<char>(byte & 0xFF);
        }
    } catch (...) {
        console_.println("invalid session hex");
        logger_.warn("cli reply failed: invalid session_hex format");
        return;
    }

    ResponderValue value;
    if (!responder_lru_.get_first_and_move_to_tail(sid, value)) {
        console_.println("unknown session id");
        logger_.warn("cli reply failed: unknown session id " + session_hex_in);
        return;
    }
    if (value.addr_nnh.is_unspecified() || value.port_nnh == 0) {
        console_.println("session missing nnh address; cannot reply");
        logger_.warn("cli reply failed: missing nnh address");
        return;
    }

    draughts::DraughtsPacket p{};
    draughts::fill_exit_pk(p.pk_ph_tmp);
    std::memcpy(p.params.pk_pph_tmp, value.pk_pph_tmp.data(), draughts::kPkSize);
    std::memcpy(p.params.pk_init_tmp, value.pk_init_tmp.data(), draughts::kPkSize);
    addr_to_bytes(value.addr_nnh, value.port_nnh, p.params.addr_nnh);
    std::memcpy(p.params.c_addr_real_sender, value.c_addr_real_sender.data(), draughts::kAddrSize);

    draughts::crypto::PubKey pk_init{};
    std::memcpy(pk_init.data(), value.pk_init_tmp.data(), draughts::kPkSize);
    std::memcpy(p.params.c_addr_real_receiver, value.c_addr_real_sender.data(), draughts::kAddrSize);
    draughts::zero_addr(p.params.c_addr_real_sender);

    p.params.x = -2.0;
    p.params.magic_num = cfg_.magic_num;
    std::memcpy(p.session_id, sid.data(), draughts::kSessionIdSize);

    std::uint8_t pt[draughts::kDataSize] = {};
    encode_payload(text, pt);

    auto secret = identity_.DeriveSharedSecret(pk_init);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    std::memcpy(p.c_data, pt, draughts::kDataSize);
    crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);

    if (!send_packet_to(p, value.addr_ph, value.port_ph)) {
        console_.println("failed to send reply to out node");
        logger_.warn("cli reply failed session=" + session_hex(sid));
        return;
    }

    logger_.info("cli send reply session=" + session_hex(sid) +
                 " outnode=" + endpoint_to_string(value.addr_ph, value.port_ph));
    console_.println("sent reply session=" + session_hex(sid) + " to out node");
}

// ------------------- UDP receive -------------------

void DraughtsApp::do_receive() {
    sock_.async_receive_from(boost::asio::buffer(rxbuf_), remote_,
                             [this](boost::system::error_code ec, std::size_t n) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted) {
                logger_.warn(std::string("draughts recv error: ") + ec.message());
            }
            return;
        }
        if (n != draughts::kPacketSize) {
            logger_.warn("dropping draughts packet with invalid size");
            do_receive();
            return;
        }
        on_datagram(rxbuf_, remote_);
        do_receive();
    });
}

void DraughtsApp::on_datagram(const std::array<uint8_t, draughts::kPacketSize>& bytes,
                              const udp::endpoint& from) {
    draughts::DraughtsPacket p{};
    std::memcpy(&p, bytes.data(), draughts::kPacketSize);
    logger_.info("recv packet from " + peer_label_for(from.address().to_v4(), from.port()));

    if (draughts::is_exit_pk(p.pk_ph_tmp)) {
        handle_exit_packet(p, from);
    } else {
        handle_random_walk(p, from);
    }
}

void DraughtsApp::handle_exit_packet(draughts::DraughtsPacket& p, const udp::endpoint& from) {
    if (p.params.magic_num != cfg_.magic_num) {
        logger_.warn("exit packet magic mismatch");
        return;
    }

    std::string sid = session_id_from_bytes(p.session_id);
    double x = p.params.x;

    if (approx_eq(x, -1.0)) {
        auto it = initiator_sessions_.find(sid);
        if (it != initiator_sessions_.end()) {
            std::string text;
            std::array<std::uint8_t, draughts::kDataSize> tmp{};
            std::memcpy(tmp.data(), p.c_data, draughts::kDataSize);
            auto secret = it->second.init_key.DeriveSharedSecret(it->second.resp_pub);
            auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
            crypto::CommutativeCipher::TransformInPlace(tmp.data(), draughts::kDataSize, key_iv.first, key_iv.second);
            if (!decode_payload(tmp.data(), text)) {
                logger_.warn("failed to decrypt response payload");
                return;
            }

            logger_.info("recv reply session=" + session_hex(sid));
            inbox_.push_back(InboxItem{true, session_hex(sid), text, ""});
            console_.println("[REPLY] session=" + session_hex(sid) + " text=\"" + text + "\"");
            initiator_sessions_.erase(it);
            initiator_session_ids_.erase(sid);
            return;
        }
        if (initiator_session_ids_.count(sid)) {
            logger_.warn("missing initiator session key for reply");
            return;
        }

        draughts::crypto::PubKey pk_init{};
        std::memcpy(pk_init.data(), p.params.pk_init_tmp, draughts::kPkSize);
        auto secret = identity_.DeriveSharedSecret(pk_init);
        auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
        crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);

        std::string text;
        if (!decode_payload(p.c_data, text)) {
            logger_.warn("failed to decode request payload");
            return;
        }

        std::array<std::uint8_t, draughts::kAddrSize> c_addr_real_sender{};
        std::memcpy(c_addr_real_sender.data(), p.params.c_addr_real_sender, draughts::kAddrSize);
        if (!transform_real_addr(c_addr_real_sender.data(), identity_, pk_init,
                                      "responder_decrypt_init", "request", "c_addr_real_sender",
                                      "decrypt",
                                      "identity_priv", "packet.pk_init_tmp",
                                      "",
                                      "packet.pk_init_tmp",
                                      sid)) {
            logger_.warn("failed to decrypt c_addr_real_sender at responder");
            return;
        }

        logger_.info("recv request session=" + session_hex(sid) +
                     " from=" + endpoint_to_string(from.address().to_v4(), from.port()));
        ResponderValue value{};
        value.addr_ph = from.address().to_v4();
        value.port_ph = from.port();
        std::memcpy(value.pk_pph_tmp.data(), p.params.pk_pph_tmp, draughts::kPkSize);
        std::memcpy(value.pk_init_tmp.data(), p.params.pk_init_tmp, draughts::kPkSize);
        if (!bytes_to_addr(p.params.addr_nnh, value.addr_nnh, value.port_nnh)) {
            value.addr_nnh = address_v4::any();
            value.port_nnh = 0;
        }
        std::memcpy(value.c_addr_real_sender.data(), c_addr_real_sender.data(), draughts::kAddrSize);
        value.created_ms = now_ms();
        responder_lru_.insert_head(sid, value);

        inbox_.push_back(InboxItem{false, session_hex(sid), text, endpoint_to_string(from.address().to_v4(), from.port())});
        console_.println("[REQUEST] session=" + session_hex(sid) + " from=" + endpoint_to_string(from.address().to_v4(), from.port())
                         + " text=\"" + text + "\"");
        return;
    }

    if (approx_eq(x, -2.0)) {
        address_v4 nh_addr;
        uint16_t nh_port = 0;
        if (!bytes_to_addr(p.params.addr_nnh, nh_addr, nh_port) || draughts::is_zero_addr(p.params.addr_nnh)) {
            logger_.warn("invalid next hop for response bootstrap");
            return;
        }
        draughts::crypto::PubKey nh_pub{};
        if (nh_port == 0 || !get_peer_pubkey_by_endpoint(nh_addr, nh_port, nh_pub)) {
            logger_.warn("next hop info not found for response bootstrap");
            return;
        }

        std::string exclude_peer_id;
        auto from_desc = node_.lookup_peer_by_draughts_endpoint(from.address().to_v4(), from.port());
        if (from_desc) exclude_peer_id = from_desc->peer_id;

        std::string nh_peer_id;
        auto nh_desc = node_.lookup_peer_by_draughts_endpoint(nh_addr, nh_port);
        if (nh_desc) nh_peer_id = nh_desc->peer_id;

        address_v4 nnh_addr;
        uint16_t nnh_port = 0;
        draughts::crypto::PubKey nnh_pub{};
        if (!pick_nnh_for_peer_id(nh_peer_id, exclude_peer_id, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh for response bootstrap");
            return;
        }

        draughts::crypto::Sm2KeyPair ph_tmp;
        auto ph_pub = ph_tmp.public_key_raw();
        std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);

        p.params.x = -std::fabs(cfg_.ciplc_x0);
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);

        if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
            logger_.warn("failed to encrypt response params");
            return;
        }

        send_packet_to(p, nh_addr, nh_port);
        return;
    }

    logger_.warn("exit packet with unknown x value");
}

void DraughtsApp::handle_random_walk(draughts::DraughtsPacket& p, const udp::endpoint& from) {
    if (!decrypt_params(p)) {
        logger_.warn("failed to decrypt params");
        return;
    }
    if (p.params.magic_num != cfg_.magic_num) {
        logger_.warn("magic mismatch");
        return;
    }

    std::string sid = session_id_from_bytes(p.session_id);
    bool response_flow = draughts::is_zero_addr(p.params.c_addr_real_sender);
    bool response_first_hop = response_flow && (p.params.x < 0.0);
    auto from_desc = node_.lookup_peer_by_draughts_endpoint(from.address().to_v4(), from.port());
    std::string from_peer_id = from_desc ? from_desc->peer_id : "";

    if (approx_eq(p.params.x, 0.0)) {
        if (is_zero_pk_bytes(p.params.pk_pph_tmp) || draughts::is_exit_pk(p.params.pk_pph_tmp)) {
            logger_.warn("invalid pk_pph_tmp for outnode");
            return;
        }
        if (response_flow) {
            draughts::crypto::PubKey pk_pph{};
            std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph,
                                          "response_outnode_peel", "response", "c_addr_real_receiver",
                                          "decrypt",
                                          "identity_priv", "packet.pk_pph_tmp",
                                          peer_id_for_pubkey(pk_pph),
                                          "packet.pk_pph_tmp",
                                          sid)) {
                logger_.warn("failed to peel c_addr_real_receiver at outnode");
                return;
            }
        } else {
            draughts::crypto::PubKey pk_pph{};
            std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph,
                                     "request_outnode_peel", "request", "c_addr_real_receiver",
                                     "decrypt",
                                     "identity_priv", "packet.pk_pph_tmp",
                                     from_peer_id,
                                     "packet.pk_pph_tmp",
                                     sid)) {
                logger_.warn("failed to peel c_addr_real_receiver at outnode");
                return;
            }
        }

        address_v4 responder_addr;
        uint16_t responder_port = 0;
        if (!bytes_to_addr(p.params.c_addr_real_receiver, responder_addr, responder_port) ||
            draughts::is_zero_addr(p.params.c_addr_real_receiver)) {
            logger_.warn("invalid responder address at outnode");
            return;
        }
        if (responder_port == 0) {
            logger_.warn("responder port missing at outnode");
            return;
        }

        std::memcpy(p.params.pk_pph_tmp, p.pk_ph_tmp, draughts::kPkSize);
        p.params.x = -1.0;
        draughts::fill_exit_pk(p.pk_ph_tmp);
        send_packet_to(p, responder_addr, responder_port);
        return;
    }

    bool can_continue = !draughts::is_zero_addr(p.params.addr_nnh);
    address_v4 nh_addr;
    uint16_t nh_port = 0;
    if (can_continue && !bytes_to_addr(p.params.addr_nnh, nh_addr, nh_port)) {
        can_continue = false;
    }

    if (response_first_hop && !can_continue) {
        logger_.warn("response first hop missing nnh; dropping");
        return;
    }

    bool do_continue = false;
    if (response_flow) {
        do_continue = response_first_hop;
        if (response_first_hop) {
            p.params.x = std::fabs(p.params.x);
        }
    } else {
        Ciplc ciplc = ciplc_;
        ciplc.x = p.params.x;
        do_continue = can_continue && ciplc.step_and_decide(rng_);
        p.params.x = ciplc.x;
    }

    std::string exclude_peer_id;
    if (from_desc) exclude_peer_id = from_desc->peer_id;

    if (do_continue) {
        draughts::crypto::PubKey nh_pub{};
        if (nh_port == 0 || !get_peer_pubkey_by_endpoint(nh_addr, nh_port, nh_pub)) {
            logger_.warn("next hop pubkey not found; dropping");
            return;
        }

        std::string nh_peer_id;
        auto nh_desc = node_.lookup_peer_by_draughts_endpoint(nh_addr, nh_port);
        if (nh_desc) nh_peer_id = nh_desc->peer_id;

        address_v4 nnh_addr;
        uint16_t nnh_port = 0;
        draughts::crypto::PubKey nnh_pub{};
        if (!pick_nnh_for_peer_id(nh_peer_id, exclude_peer_id, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh for relay");
            return;
        }
        auto nnh_desc = node_.lookup_peer_by_draughts_endpoint(nnh_addr, nnh_port);
        std::string nnh_peer_id = nnh_desc ? nnh_desc->peer_id : "";

        if (is_zero_pk_bytes(p.params.pk_pph_tmp) || draughts::is_exit_pk(p.params.pk_pph_tmp)) {
            logger_.warn("invalid pk_pph_tmp for relay");
            return;
        }
        draughts::crypto::PubKey pk_pph{};
        std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
        std::array<uint8_t, draughts::kPkSize> old_ph{};
        std::memcpy(old_ph.data(), p.pk_ph_tmp, draughts::kPkSize);

        draughts::crypto::Sm2KeyPair ph_tmp;
        auto ph_pub = ph_tmp.public_key_raw();
        std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);

        if (!response_flow) {
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph,
                                     "request_relay_peel", "request", "c_addr_real_receiver",
                                     "decrypt",
                                     "identity_priv", "packet.pk_pph_tmp",
                                     from_peer_id,
                                     "packet.pk_pph_tmp",
                                     sid)) {
                logger_.warn("failed to peel c_addr_real_receiver at relay");
                return;
            }
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, nnh_pub,
                                     "request_relay_add", "request", "c_addr_real_receiver",
                                     "encrypt",
                                     "identity_priv", "nnh_pub",
                                     nnh_peer_id,
                                     peer_label_for(nnh_addr, nnh_port),
                                     sid)) {
                logger_.warn("failed to add layer to c_addr_real_receiver at relay");
                return;
            }
            std::memcpy(p.params.pk_pph_tmp, old_ph.data(), draughts::kPkSize);
        } else {
            if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nnh_pub,
                                          "response_first_hop_add", "response", "c_addr_real_receiver",
                                          "encrypt",
                                          "ph_tmp_priv", "res_out_pub",
                                          nnh_peer_id,
                                          peer_label_for(nnh_addr, nnh_port),
                                          sid)) {
                logger_.warn("failed to add layer to c_addr_real_receiver at response first hop");
                return;
            }
        }
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);

        if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
            logger_.warn("failed to encrypt params for relay");
            return;
        }

        send_packet_to(p, nh_addr, nh_port);
        return;
    }

    address_v4 outnode_addr;
    uint16_t outnode_port = 0;
    draughts::crypto::PubKey outnode_pub{};
    std::string outnode_peer_id;
    bool outnode_ok = false;
    if (can_continue && !draughts::is_zero_addr(p.params.addr_nnh)) {
        if (nh_port != 0 && get_peer_pubkey_by_endpoint(nh_addr, nh_port, outnode_pub)) {
            outnode_addr = nh_addr;
            outnode_port = nh_port;
            auto nh_desc = node_.lookup_peer_by_draughts_endpoint(nh_addr, nh_port);
            if (nh_desc) outnode_peer_id = nh_desc->peer_id;
            outnode_ok = true;
        }
    }
    if (!outnode_ok) {
        auto nh_desc = node_.pick_random_active_except(exclude_peer_id);
        if (!nh_desc) {
            logger_.warn("no neighbors to pick outnode");
            return;
        }
        outnode_addr = addr_from_bytes(nh_desc->ip);
        outnode_port = nh_desc->draughts_port;
        if (!get_peer_pubkey_by_endpoint(outnode_addr, outnode_port, outnode_pub)) {
            logger_.warn("outnode pubkey not found");
            return;
        }
        outnode_peer_id = nh_desc->peer_id;
        outnode_ok = true;
    }
    if (outnode_port == 0) {
        logger_.warn("outnode port missing");
        return;
    }

    address_v4 nnh_addr;
    uint16_t nnh_port = 0;
    draughts::crypto::PubKey nnh_pub{};
    if (!response_flow) {
        if (!pick_nnh_for_peer_id(outnode_peer_id, exclude_peer_id, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh for outnode leg");
            return;
        }
    }

    std::array<uint8_t, draughts::kPkSize> prev_ph{};
    std::memcpy(prev_ph.data(), p.pk_ph_tmp, draughts::kPkSize);
    draughts::crypto::Sm2KeyPair ph_tmp;
    auto ph_pub = ph_tmp.public_key_raw();

    if (is_zero_pk_bytes(p.params.pk_pph_tmp) || draughts::is_exit_pk(p.params.pk_pph_tmp)) {
        logger_.warn("invalid pk_pph_tmp for exit");
        return;
    }
    draughts::crypto::PubKey pk_pph{};
    std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
    if (response_flow) {
        if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph,
                                      "response_exit_peel", "response", "c_addr_real_receiver",
                                      "decrypt",
                                      "identity_priv", "packet.pk_pph_tmp",
                                      peer_id_for_pubkey(pk_pph),
                                      "packet.pk_pph_tmp",
                                      sid)) {
            logger_.warn("failed to peel c_addr_real_receiver at response exit");
            return;
        }
    } else {
        if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph,
                                 "request_exit_peel", "request", "c_addr_real_receiver",
                                 "decrypt",
                                 "identity_priv", "packet.pk_pph_tmp",
                                 from_peer_id,
                                 "packet.pk_pph_tmp",
                                 sid)) {
            logger_.warn("failed to peel c_addr_real_receiver at exit");
            return;
        }
        auto nnh_desc = node_.lookup_peer_by_draughts_endpoint(nnh_addr, nnh_port);
        std::string nnh_peer_id = nnh_desc ? nnh_desc->peer_id : "";
        if (!transform_real_addr(p.params.c_addr_real_sender, ph_tmp, nnh_pub,
                                      "request_exit_add", "request", "c_addr_real_sender",
                                      "encrypt",
                                      "ph_tmp_priv", "res2nd_pub",
                                      nnh_peer_id,
                                      peer_label_for(nnh_addr, nnh_port),
                                      sid)) {
            logger_.warn("failed to add layer to c_addr_real_sender at exit (request)");
            return;
        }
    }

    p.params.x = 0.0;
    if (!response_flow) {
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
    } else {
        draughts::zero_addr(p.params.addr_nnh);
    }

    std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);
    std::memcpy(p.params.pk_pph_tmp, prev_ph.data(), draughts::kPkSize);

    if (!encrypt_params_for_next_hop(p, outnode_pub, ph_tmp)) {
        logger_.warn("failed to encrypt params for outnode");
        return;
    }

    send_packet_to(p, outnode_addr, outnode_port);
}

bool DraughtsApp::decrypt_params(draughts::DraughtsPacket& p) {
    draughts::crypto::PubKey pk_ph{};
    std::memcpy(pk_ph.data(), p.pk_ph_tmp, draughts::kPkSize);
    auto secret = identity_.DeriveSharedSecret(pk_ph);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);

    auto* params_bytes = reinterpret_cast<std::uint8_t*>(&p.params);
    crypto::CommutativeCipher::TransformInPlace(params_bytes, sizeof(draughts::DraughtsParams), key_iv.first, key_iv.second);
    return true;
}

bool DraughtsApp::encrypt_params_for_next_hop(draughts::DraughtsPacket& p,
                                              const draughts::crypto::PubKey& next_pubkey,
                                              const draughts::crypto::Sm2KeyPair& ph_keypair) {
    auto secret = ph_keypair.DeriveSharedSecret(next_pubkey);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    auto* params_bytes = reinterpret_cast<std::uint8_t*>(&p.params);
    crypto::CommutativeCipher::TransformInPlace(params_bytes, sizeof(draughts::DraughtsParams), key_iv.first, key_iv.second);
    return true;
}

bool DraughtsApp::send_packet_to(const draughts::DraughtsPacket& p,
                                 const address_v4& addr,
                                 uint16_t port) {
    if (port == 0) return false;
    udp::endpoint ep(addr, port);
    auto buf = std::make_shared<std::array<uint8_t, draughts::kPacketSize>>();
    std::memcpy(buf->data(), &p, draughts::kPacketSize);
    logger_.info("send packet to " + peer_label_for(addr, port));
    sock_.async_send_to(boost::asio::buffer(*buf), ep, [buf](auto, auto) {});
    return true;
}

std::string DraughtsApp::peer_label_for(const address_v4& addr, uint16_t port) const {
    auto desc = node_.lookup_peer_by_draughts_endpoint(addr, port);
    auto ep = endpoint_to_string(addr, port);
    if (desc && !desc->peer_id.empty()) {
        return desc->peer_id + "@" + ep;
    }
    return ep;
}

void DraughtsApp::init_trace() {
    if (trace_ready_) return;
    if (cfg_.peer_id.empty()) return;
    try {
        namespace fs = std::filesystem;
        fs::create_directories("trace");
        trace_dir_ = "trace/" + cfg_.peer_id + "_" + std::to_string(::getpid()) + "_" + std::to_string(now_ms());
        fs::create_directories(trace_dir_ + "/keys");
        trace_out_.open(trace_dir_ + "/trace.log", std::ios::out | std::ios::app);
        trace_ready_ = trace_out_.is_open();
    } catch (...) {
        trace_ready_ = false;
    }
}

std::string DraughtsApp::trace_store_key(const std::string& pem, const std::string& prefix) {
    if (!trace_ready_ || pem.empty()) return "";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(pem.data()), pem.size(), digest);
    std::ostringstream hex;
    for (auto b : digest) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::string key = prefix + "_" + hex.str();
    auto it = trace_key_cache_.find(key);
    if (it != trace_key_cache_.end()) return it->second;

    std::string rel = "keys/" + key + ".pem";
    std::string path = trace_dir_ + "/" + rel;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (out.is_open()) {
        out << pem;
        out.close();
        trace_key_cache_[key] = rel;
        return rel;
    }
    return "";
}

std::string DraughtsApp::trace_store_pub_raw(const draughts::crypto::PubKey& raw) {
    try {
        auto pem = draughts::crypto::Sm2KeyPair::PublicKeyPemFromRaw(raw);
        return trace_store_key(pem, "pub");
    } catch (...) {
        return "";
    }
}

void DraughtsApp::trace_real_addr_transform(const char* stage,
                                            const char* flow,
                                            const char* field,
                                            const char* op,
                                            const char* priv_role,
                                            const char* peer_role,
                                            const std::string& peer_id,
                                            const std::string& peer_label,
                                            const std::string& sid,
                                            const std::uint8_t before[draughts::kAddrSize],
                                            const std::uint8_t after[draughts::kAddrSize],
                                            const draughts::crypto::Sm2KeyPair& priv_key,
                                            const draughts::crypto::PubKey& peer_pub) {
    if (!trace_ready_) return;
    std::lock_guard<std::mutex> lk(trace_mu_);
    std::string priv_pem;
    try {
        priv_pem = priv_key.PrivateKeyPem();
    } catch (...) {
        return;
    }
    std::string priv_file = trace_store_key(priv_pem, "priv");
    std::string pub_file = trace_store_pub_raw(peer_pub);
    std::string before_hex = bytes_to_hex(before, draughts::kAddrSize);
    std::string after_hex = bytes_to_hex(after, draughts::kAddrSize);
    trace_out_ << "{"
               << "\"ts_ms\":" << now_ms() << ","
               << "\"node_id\":\"" << json_escape(cfg_.peer_id) << "\","
               << "\"session\":\"" << session_hex(sid) << "\","
               << "\"flow\":\"" << flow << "\","
               << "\"stage\":\"" << stage << "\","
               << "\"field\":\"" << field << "\","
               << "\"op\":\"" << json_escape(op ? op : "") << "\","
               << "\"priv_role\":\"" << json_escape(priv_role ? priv_role : "") << "\","
               << "\"peer_role\":\"" << json_escape(peer_role ? peer_role : "") << "\","
               << "\"peer_id\":\"" << json_escape(peer_id) << "\","
               << "\"peer_label\":\"" << json_escape(peer_label) << "\","
               << "\"before\":\"" << before_hex << "\","
               << "\"after\":\"" << after_hex << "\","
               << "\"priv_key\":\"" << priv_file << "\","
               << "\"peer_pub\":\"" << pub_file << "\""
               << "}\n";
    trace_out_.flush();
}

bool DraughtsApp::transform_real_addr(std::uint8_t addr[draughts::kAddrSize],
                                      const draughts::crypto::Sm2KeyPair& priv_key,
                                      const draughts::crypto::PubKey& peer_pub,
                                      const char* stage,
                                      const char* flow,
                                      const char* field,
                                      const char* op,
                                      const char* priv_role,
                                      const char* peer_role,
                                      const std::string& peer_id,
                                      const std::string& peer_label,
                                      const std::string& sid) {
    std::array<std::uint8_t, draughts::kAddrSize> before{};
    std::memcpy(before.data(), addr, draughts::kAddrSize);
    if (!transform_addr_layer(addr, priv_key, peer_pub)) return false;
    std::array<std::uint8_t, draughts::kAddrSize> after{};
    std::memcpy(after.data(), addr, draughts::kAddrSize);
    trace_real_addr_transform(stage, flow, field, op, priv_role, peer_role, peer_id, peer_label,
                              sid, before.data(), after.data(), priv_key, peer_pub);
    return true;
}

bool DraughtsApp::pick_nh_nnh(address_v4& nh_addr,
                              uint16_t& nh_port,
                              draughts::crypto::PubKey& nh_pub,
                              address_v4& nnh_addr,
                              uint16_t& nnh_port,
                              draughts::crypto::PubKey& nnh_pub,
                              const std::string& exclude_peer_id) {
    auto nh_desc = node_.pick_random_active_except(exclude_peer_id);
    if (!nh_desc) return false;
    nh_addr = addr_from_bytes(nh_desc->ip);
    nh_port = nh_desc->draughts_port;
    if (nh_port == 0) return false;

    if (!get_peer_pubkey_by_endpoint(nh_addr, nh_port, nh_pub)) return false;

    return pick_nnh_for_peer_id(nh_desc->peer_id, exclude_peer_id, nnh_addr, nnh_port, nnh_pub);
}

bool DraughtsApp::pick_nnh_for_peer_id(const std::string& nh_peer_id,
                                       const std::string& exclude_peer_id,
                                       address_v4& nnh_addr,
                                       uint16_t& nnh_port,
                                       draughts::crypto::PubKey& nnh_pub) {
    bool nnh_ok = false;
    if (!nh_peer_id.empty()) {
        auto nnh_id = node_.pick_nnh_for(nh_peer_id, exclude_peer_id);
        if (nnh_id) {
            auto nnh_desc = node_.lookup_peer(*nnh_id);
            if (nnh_desc) {
                nnh_addr = addr_from_bytes(nnh_desc->ip);
                nnh_port = nnh_desc->draughts_port;
                nnh_ok = (nnh_port != 0);
            }
        }
    }

    if (!nnh_ok) {
        auto act = node_.active_neighbors();
        std::vector<proto::PeerDescriptor> candidates;
        for (const auto& d : act) {
            if (!nh_peer_id.empty() && d.peer_id == nh_peer_id) continue;
            if (!exclude_peer_id.empty() && d.peer_id == exclude_peer_id) continue;
            candidates.push_back(d);
        }
        if (!candidates.empty()) {
            std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
            auto pick = candidates[dist(rng_)];
            nnh_addr = addr_from_bytes(pick.ip);
            nnh_port = pick.draughts_port;
            nnh_ok = (nnh_port != 0);
        }
    }

    if (!nnh_ok) return false;
    if (!get_peer_pubkey_by_endpoint(nnh_addr, nnh_port, nnh_pub)) return false;
    return true;
}

std::string DraughtsApp::session_hex(const std::string& sid) {
    return bytes_to_hex(reinterpret_cast<const uint8_t*>(sid.data()), sid.size());
}

std::string DraughtsApp::bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string DraughtsApp::addr_to_string(const address_v4& addr) {
    return addr.to_string();
}

std::string DraughtsApp::endpoint_to_string(const address_v4& addr, uint16_t port) {
    return addr.to_string() + ":" + std::to_string(port);
}

bool DraughtsApp::addr_from_string(const std::string& s, address_v4& out) {
    boost::system::error_code ec;
    auto addr = address_v4::from_string(s, ec);
    if (ec) return false;
    out = addr;
    return true;
}

bool DraughtsApp::endpoint_from_string(const std::string& s, address_v4& out, uint16_t& port) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos) return false;
    auto ip = s.substr(0, pos);
    auto ps = s.substr(pos + 1);
    if (ip.empty() || ps.empty()) return false;
    if (!addr_from_string(ip, out)) return false;
    int port_i = 0;
    try {
        port_i = std::stoi(ps);
    } catch (...) {
        return false;
    }
    if (port_i <= 0 || port_i > 65535) return false;
    port = static_cast<uint16_t>(port_i);
    return true;
}

void DraughtsApp::addr_to_bytes(const address_v4& addr,
                                uint16_t port,
                                std::uint8_t out_bytes[draughts::kAddrSize]) {
    auto bytes = addr.to_bytes();
    std::memcpy(out_bytes, bytes.data(), 4);
    out_bytes[4] = static_cast<uint8_t>((port >> 8) & 0xFF);
    out_bytes[5] = static_cast<uint8_t>(port & 0xFF);
}

bool DraughtsApp::bytes_to_addr(const std::uint8_t in_bytes[draughts::kAddrSize],
                                address_v4& out,
                                uint16_t& port) {
    address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), in_bytes, 4);
    out = address_v4(bytes);
    port = (static_cast<uint16_t>(in_bytes[4]) << 8) | static_cast<uint16_t>(in_bytes[5]);
    return true;
}

std::string DraughtsApp::session_id_from_bytes(const std::uint8_t bytes[draughts::kSessionIdSize]) {
    return std::string(reinterpret_cast<const char*>(bytes), draughts::kSessionIdSize);
}

void DraughtsApp::random_session_id(std::uint8_t out[draughts::kSessionIdSize]) {
    for (size_t i = 0; i < draughts::kSessionIdSize; ++i) {
        out[i] = static_cast<uint8_t>(rng_() & 0xFF);
    }
}

void DraughtsApp::encode_payload(const std::string& text, std::uint8_t out[draughts::kDataSize]) {
    std::memset(out, 0, draughts::kDataSize);
    uint16_t len = static_cast<uint16_t>(std::min<std::size_t>(text.size(), draughts::kDataSize - 2));
    out[0] = static_cast<uint8_t>(len & 0xFF);
    out[1] = static_cast<uint8_t>((len >> 8) & 0xFF);
    std::memcpy(out + 2, text.data(), len);
}

bool DraughtsApp::decode_payload(const std::uint8_t in[draughts::kDataSize], std::string& text) {
    uint16_t len = static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);
    if (len > draughts::kDataSize - 2) return false;
    for (size_t i = 2 + len; i < draughts::kDataSize; ++i) {
        if (in[i] != 0) return false;
    }
    text.assign(reinterpret_cast<const char*>(in + 2), len);
    return true;
}

bool DraughtsApp::get_peer_pubkey_by_endpoint(const address_v4& addr,
                                              uint16_t port,
                                              draughts::crypto::PubKey& out_pubkey) const {
    if (port == 0) return false;
    auto desc = node_.lookup_peer_by_draughts_endpoint(addr, port);
    if (!desc) return false;
    if (desc->pubkey.empty()) return false;
    std::vector<uint8_t> raw;
    try {
        raw = b64::decode(desc->pubkey);
    } catch (...) {
        return false;
    }
    if (raw.size() != draughts::kPkSize) return false;
    std::memcpy(out_pubkey.data(), raw.data(), draughts::kPkSize);
    return true;
}

std::string DraughtsApp::peer_id_for_pubkey(const draughts::crypto::PubKey& pub) const {
    auto peers = node_.all_peers();
    for (const auto& d : peers) {
        if (d.pubkey.empty()) continue;
        std::vector<uint8_t> raw;
        try {
            raw = b64::decode(d.pubkey);
        } catch (...) {
            continue;
        }
        if (raw.size() != draughts::kPkSize) continue;
        if (std::memcmp(raw.data(), pub.data(), draughts::kPkSize) == 0) {
            return d.peer_id;
        }
    }
    return "";
}

bool DraughtsApp::resolve_peer_target(const std::string& dest,
                                      address_v4& out_addr,
                                      uint16_t& out_port,
                                      draughts::crypto::PubKey& out_pubkey,
                                      std::string& out_peer_id) const {
    address_v4 addr;
    uint16_t port = 0;
    if (endpoint_from_string(dest, addr, port)) {
        if (get_peer_pubkey_by_endpoint(addr, port, out_pubkey)) {
            out_addr = addr;
            out_port = port;
            auto desc = node_.lookup_peer_by_draughts_endpoint(addr, port);
            if (desc) out_peer_id = desc->peer_id;
            return true;
        }
        if (!cfg_.peer_info_dir.empty()) {
            namespace fs = std::filesystem;
            for (const auto& entry : fs::directory_iterator(cfg_.peer_info_dir)) {
                if (!entry.is_regular_file()) continue;
                PeerInfoFile info;
                if (!load_peer_info_file(entry.path().string(), info)) continue;
                if (info.bind_ip.empty() || info.draughts_port == 0) continue;
                if (info.bind_ip == addr.to_string() && info.draughts_port == port) {
                    std::vector<uint8_t> raw;
                    try {
                        raw = b64::decode(info.pubkey);
                    } catch (...) {
                        return false;
                    }
                    if (raw.size() != draughts::kPkSize) return false;
                    std::memcpy(out_pubkey.data(), raw.data(), draughts::kPkSize);
                    out_addr = addr;
                    out_port = port;
                    out_peer_id = info.peer_id;
                    return true;
                }
            }
        }
        return false;
    }

    // Treat as peer_id
    out_peer_id = dest;
    auto desc = node_.lookup_peer(dest);
    if (desc && desc->draughts_port != 0 && !desc->pubkey.empty()) {
        out_addr = addr_from_bytes(desc->ip);
        out_port = desc->draughts_port;
        std::vector<uint8_t> raw;
        try {
            raw = b64::decode(desc->pubkey);
        } catch (...) {
            return false;
        }
        if (raw.size() != draughts::kPkSize) return false;
        std::memcpy(out_pubkey.data(), raw.data(), draughts::kPkSize);
        return true;
    }
    if (!cfg_.peer_info_dir.empty()) {
        std::string path = cfg_.peer_info_dir + "/" + dest + ".info";
        PeerInfoFile info;
        if (load_peer_info_file(path, info)) {
            boost::system::error_code ec;
            auto addr2 = address_v4::from_string(info.bind_ip, ec);
            if (ec) return false;
            std::vector<uint8_t> raw;
            try {
                raw = b64::decode(info.pubkey);
            } catch (...) {
                return false;
            }
            if (raw.size() != draughts::kPkSize) return false;
            std::memcpy(out_pubkey.data(), raw.data(), draughts::kPkSize);
            out_addr = addr2;
            out_port = info.draughts_port;
            return true;
        }
    }
    return false;
}

void DraughtsApp::prune_sessions() {
    uint64_t now = now_ms();
    for (auto it = initiator_sessions_.begin(); it != initiator_sessions_.end(); ) {
        if (now - it->second.created_ms > cfg_.session_ttl_ms) {
            initiator_session_ids_.erase(it->first);
            it = initiator_sessions_.erase(it);
        } else {
            ++it;
        }
    }
}
