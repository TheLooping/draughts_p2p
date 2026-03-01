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

bool is_all_zero_hex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c != '0') return false;
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

void log_nh_nnh(Logger& logger,
                const std::string& nh_label,
                const std::string& nnh_label,
                const std::string& stage) {
    std::string suffix;
    if (!stage.empty()) suffix = " stage=" + stage;
    logger.info("根据下一跳" + nh_label + "选择下下跳为" + nnh_label + suffix);
}

std::string hex_bytes(const std::uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        if (i > 0) oss << "";
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

std::string bytes_header_hex(const std::uint8_t* data, std::size_t len, std::size_t n = 8) {
    n = std::min<std::size_t>(n, len);
    return "0x" + hex_bytes(data, n);
}

std::string addr_field_hex(const std::uint8_t addr[draughts::kAddrSize]) {
    return "0x" + hex_bytes(addr, draughts::kAddrSize);
}

std::string pk_field_head(const std::uint8_t pk[draughts::kPkSize], std::size_t n = 8) {
    n = std::min<std::size_t>(n, draughts::kPkSize);
    return "0x" + hex_bytes(pk, n);
}

std::string pubkey_head(const draughts::crypto::PubKey& pk, std::size_t n = 8) {
    n = std::min<std::size_t>(n, pk.size());
    return "0x" + hex_bytes(pk.data(), n);
}

std::string addr_field_readable(const std::uint8_t addr[draughts::kAddrSize]) {
    if (draughts::is_zero_addr(addr)) return addr_field_hex(addr) + "(0.0.0.0:0)";
    boost::asio::ip::address_v4::bytes_type ip_bytes{};
    std::memcpy(ip_bytes.data(), addr, 4);
    auto ip = boost::asio::ip::address_v4(ip_bytes).to_string();
    auto port = (static_cast<uint16_t>(addr[4]) << 8) | static_cast<uint16_t>(addr[5]);
    return addr_field_hex(addr) + "(" + ip + ":" + std::to_string(port) + ")";
}

std::string session_hex_from_packet(const draughts::DraughtsPacket& p) {
    return hex_bytes(p.session_id, draughts::kSessionIdSize);
}

void log_packet_construct(Logger& logger,
                          const std::string& stage,
                          const std::string& session_hex,
                          const std::string& flow) {
    logger.info("构造数据包 stage=" + stage + " flow=" + flow + " session=" + session_hex);
}

void log_packet_field_set(Logger& logger,
                          const std::string& stage,
                          const std::string& field,
                          const std::string& value) {
    logger.detail("Field 细节",
                  "stage=" + stage + " packet_field=" + field + " set_value=" + value);
}

void log_packet_snapshot(Logger& logger,
                         const std::string& stage,
                         const draughts::DraughtsPacket& p) {
    logger.detail("Packet 细节",
                  "stage=" + stage +
                  " session=" + session_hex_from_packet(p) +
                  " pk_ph_tmp_head=" + pk_field_head(p.pk_ph_tmp) +
                  " pk_pph_tmp_head=" + pk_field_head(p.params.pk_pph_tmp) +
                  " pk_init_tmp_head=" + pk_field_head(p.params.pk_init_tmp) +
                  " addr_nnh=" + addr_field_readable(p.params.addr_nnh) +
                  " c_addr_real_receiver=" + addr_field_readable(p.params.c_addr_real_receiver) +
                  " c_addr_real_sender=" + addr_field_readable(p.params.c_addr_real_sender) +
                  " topo_term=" + std::to_string(p.params.topo_term) +
                  " x=" + std::to_string(p.params.x) +
                  " magic=0x" + hex_bytes(reinterpret_cast<const std::uint8_t*>(&p.params.magic_num),
                                          sizeof(p.params.magic_num)));
}

void log_packet_cipher_snapshot(Logger& logger,
                                const std::string& stage,
                                const draughts::DraughtsPacket& p) {
    auto* params_bytes = reinterpret_cast<const std::uint8_t*>(&p.params);
    logger.detail("Packet 细节",
                  "stage=" + stage +
                  " session=" + session_hex_from_packet(p) +
                  " pk_ph_tmp_head=" + pk_field_head(p.pk_ph_tmp) +
                  " params_cipher_head=0x" + hex_bytes(params_bytes, 12) +
                  " c_data_head=0x" + hex_bytes(p.c_data, 12));
}

void log_crypto_key_usage(Logger& logger,
                          const std::string& stage,
                          const std::string& field,
                          const std::string& op,
                          const std::string& self_key_desc,
                          const std::string& peer_key_desc,
                          const std::string& before_header,
                          const std::string& after_header) {
    // Address transform logs must be emitted only by log_addr_transform_detail
    // to avoid duplicate lines for the same operation.
    if (field.rfind("c_addr_real_", 0) == 0) return;
    std::string action = "变换";
    if (op.find("encrypt") != std::string::npos) action = "加密";
    if (op.find("decrypt") != std::string::npos) action = "解密";
    logger.detail("Crypto 细节",
                  "stage=" + stage +
                  " field=" + field +
                  " op=" + op +
                  " 基于[" + self_key_desc + "]和[" + peer_key_desc + "] 执行" + action +
                  " before_header=" + before_header +
                  " after_header=" + after_header);
}

void log_addr_transform_detail(Logger& logger,
                              const std::string& stage,
                              const std::string& field,
                              const std::string& op,
                              const std::string& self_key_desc,
                              const std::string& peer_key_desc,
                              const std::string& key_desc,
                              const std::uint8_t before[draughts::kAddrSize],
                              const std::uint8_t after[draughts::kAddrSize]) {
    (void)key_desc;
    std::string action = "变换";
    if (op.find("encrypt") != std::string::npos) action = "加密";
    if (op.find("decrypt") != std::string::npos) action = "解密";
    logger.detail("Crypto 细节",
                  "stage=" + stage +
                  " field=" + field +
                  " op=" + op +
                  " 基于[" + self_key_desc + "]和[" + peer_key_desc + "] 执行" + action +
                  " before=" + addr_field_hex(before) +
                  " after=" + addr_field_hex(after));
}

void log_addr_move_detail(Logger& logger,
                          const std::string& stage,
                          const std::uint8_t sender_before[draughts::kAddrSize],
                          const std::uint8_t receiver_before[draughts::kAddrSize],
                          const std::uint8_t sender_after[draughts::kAddrSize],
                          const std::uint8_t receiver_after[draughts::kAddrSize]) {
    logger.detail("Field 细节",
                  "stage=" + stage +
                  " move=c_addr_real_sender->c_addr_real_receiver"
                  " sender_before=" + addr_field_hex(sender_before) +
                  " receiver_before=" + addr_field_hex(receiver_before) +
                  " sender_after=" + addr_field_hex(sender_after) +
                  " receiver_after=" + addr_field_hex(receiver_after));
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
      topod_(cfg_, logger_),
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
    logger_.info("收到CLI发起通信请求 dest=" + dest +
                 " responder=" + peer_label_for(resp_addr, resp_port) +
                 " responder_pub_head=" + pubkey_head(resp_pub));

    // End-to-end init key (per-session) for initiator address + payload.
    draughts::crypto::Sm2KeyPair init_tmp;
    std::array<uint8_t, draughts::kSessionIdSize> sid_bytes{};
    std::string sid;
    do {
        random_session_id(sid_bytes.data());
        sid = session_id_from_bytes(sid_bytes.data());
    } while (initiator_sessions_.count(sid));
    logger_.detail("Session 细节",
                   "stage=cli_send_new_session action=generate_session_id sid=" + session_hex(sid));

    InitiatorSession session{};
    session.init_key = std::move(init_tmp);
    session.resp_pub = resp_pub;
    session.resp_addr = resp_addr;
    session.resp_port = resp_port;
    session.resp_peer_id = resp_peer_id;
    session.last_used_ms = now_ms();

    initiator_session_ids_.insert(sid);
    auto [it, inserted] = initiator_sessions_.emplace(sid, std::move(session));
    if (!inserted) {
        console_.println("failed to create session (collision)");
        logger_.warn("cli send failed: session collision");
        initiator_session_ids_.erase(sid);
        return;
    }
    logger_.detail("Session 细节",
                   "stage=cli_send_new_session action=store sid=" + session_hex(sid) +
                   " key=session_id value={resp_peer=" + it->second.resp_peer_id +
                   ",resp_ep=" + endpoint_to_string(it->second.resp_addr, it->second.resp_port) +
                   ",resp_pub_head=" + pubkey_head(it->second.resp_pub) + "}");

    if (!send_request_with_session(sid, it->second, text)) {
        initiator_session_ids_.erase(sid);
        initiator_sessions_.erase(sid);
        return;
    }
}

void DraughtsApp::cmd_send_session(const std::string& session_hex_in, const std::string& text) {
    if (session_hex_in.empty() || text.empty()) {
        console_.println("usage: send_session <session_hex> <text>");
        return;
    }
    logger_.info("cli send_session session=" + session_hex_in + " text_len=" + std::to_string(text.size()));

    std::string sid;
    if (!parse_session_hex(session_hex_in, sid)) {
        console_.println("invalid session hex");
        logger_.warn("cli send_session failed: invalid session_hex");
        return;
    }

    auto it = initiator_sessions_.find(sid);
    if (it == initiator_sessions_.end()) {
        std::vector<std::string> sample_ids;
        sample_ids.reserve(3);
        for (const auto& kv : initiator_sessions_) {
            sample_ids.push_back(session_hex(kv.first));
            if (sample_ids.size() >= 3) break;
        }
        std::sort(sample_ids.begin(), sample_ids.end());
        std::ostringstream known_oss;
        known_oss << "{";
        for (size_t i = 0; i < sample_ids.size(); ++i) {
            if (i > 0) known_oss << ",";
            known_oss << sample_ids[i];
        }
        known_oss << "}";
        console_.println("unknown session id; use inbox/requests里的session，或先执行send创建会话");
        logger_.warn("cli send_session failed: unknown session id " + session_hex_in +
                     " known_sessions_count=" + std::to_string(initiator_sessions_.size()) +
                     " known_sessions_sample=" + known_oss.str() +
                     (is_all_zero_hex(session_hex_in) ? " hint=placeholder_zero_session_id" : ""));
        return;
    }
    logger_.detail("Session 细节",
                   "stage=cli_send_session action=get sid=" + session_hex(sid) +
                   " key=session_id value={resp_peer=" + it->second.resp_peer_id +
                   ",resp_ep=" + endpoint_to_string(it->second.resp_addr, it->second.resp_port) +
                   ",resp_pub_head=" + pubkey_head(it->second.resp_pub) + "}");
    initiator_session_ids_.insert(sid);

    if (!send_request_with_session(sid, it->second, text)) {
        logger_.warn("cli send_session failed session=" + session_hex(sid));
        return;
    }
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
    if (!parse_session_hex(session_hex_in, sid)) {
        console_.println("invalid session hex");
        logger_.warn("cli reply failed: invalid session_hex");
        return;
    }

    ResponderValue value;
    if (!responder_lru_.get_first_and_move_to_tail(sid, value)) {
        console_.println("unknown session id");
        logger_.warn("cli reply failed: unknown session id " + session_hex_in);
        return;
    }
    logger_.detail("Session 细节",
                   "stage=cli_reply action=get sid=" + session_hex(sid) +
                   " key=session_id value={addr_ph=" + endpoint_to_string(value.addr_ph, value.port_ph) +
                   ",addr_nnh=" + endpoint_to_string(value.addr_nnh, value.port_nnh) +
                   ",pk_pph_tmp_head=" + pubkey_head(value.pk_pph_tmp) +
                   ",pk_init_tmp_head=" + pubkey_head(value.pk_init_tmp) +
                   ",topo_term=" + std::to_string(value.topo_term) + "}");
    if (value.addr_nnh.is_unspecified() || value.port_nnh == 0) {
        console_.println("session missing nnh address; cannot reply");
        logger_.warn("cli reply failed: missing nnh address");
        return;
    }
    const std::string sid_hex = session_hex(sid);

    draughts::DraughtsPacket p{};
    log_packet_construct(logger_, "cli_reply_build_response", sid_hex, "response");
    draughts::fill_exit_pk(p.pk_ph_tmp);
    log_packet_field_set(logger_, "cli_reply_build_response", "pk_ph_tmp", "EXIT_MARK(0xEE)");
    std::memcpy(p.params.pk_pph_tmp, value.pk_pph_tmp.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "cli_reply_build_response", "params.pk_pph_tmp", pubkey_head(value.pk_pph_tmp));
    std::memcpy(p.params.pk_init_tmp, value.pk_init_tmp.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "cli_reply_build_response", "params.pk_init_tmp", pubkey_head(value.pk_init_tmp));
    addr_to_bytes(value.addr_nnh, value.port_nnh, p.params.addr_nnh);
    log_packet_field_set(logger_, "cli_reply_build_response", "params.addr_nnh", addr_field_readable(p.params.addr_nnh));
    std::memcpy(p.params.c_addr_real_sender, value.c_addr_real_sender.data(), draughts::kAddrSize);
    log_packet_field_set(logger_, "cli_reply_build_response", "params.c_addr_real_sender", addr_field_readable(p.params.c_addr_real_sender));

    std::uint8_t sender_before[draughts::kAddrSize]{};
    std::uint8_t receiver_before[draughts::kAddrSize]{};
    std::memcpy(sender_before, p.params.c_addr_real_sender, draughts::kAddrSize);
    std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);

    draughts::crypto::PubKey pk_init{};
    std::memcpy(pk_init.data(), value.pk_init_tmp.data(), draughts::kPkSize);
    std::memcpy(p.params.c_addr_real_receiver, value.c_addr_real_sender.data(), draughts::kAddrSize);
    draughts::zero_addr(p.params.c_addr_real_sender);
    log_addr_move_detail(logger_,
                         "cli_reply_build_response",
                         sender_before,
                         receiver_before,
                         p.params.c_addr_real_sender,
                         p.params.c_addr_real_receiver);
    log_packet_field_set(logger_, "cli_reply_build_response", "params.c_addr_real_receiver", addr_field_readable(p.params.c_addr_real_receiver));
    log_packet_field_set(logger_, "cli_reply_build_response", "params.c_addr_real_sender", addr_field_readable(p.params.c_addr_real_sender));
    p.params.topo_term = value.topo_term;
    log_packet_field_set(logger_, "cli_reply_build_response", "params.topo_term", std::to_string(value.topo_term));
    p.params.x = -2.0;
    log_packet_field_set(logger_, "cli_reply_build_response", "params.x", "-2.0");
    p.params.magic_num = cfg_.magic_num;
    log_packet_field_set(logger_, "cli_reply_build_response", "params.magic_num", "0x" + hex_bytes(reinterpret_cast<const std::uint8_t*>(&cfg_.magic_num), sizeof(cfg_.magic_num)));
    std::memcpy(p.session_id, sid.data(), draughts::kSessionIdSize);
    log_packet_field_set(logger_, "cli_reply_build_response", "session_id", sid_hex);

    std::uint8_t pt[draughts::kDataSize] = {};
    encode_payload(text, pt);

    auto secret = identity_.DeriveSharedSecret(pk_init);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    std::memcpy(p.c_data, pt, draughts::kDataSize);
    std::array<std::uint8_t, draughts::kDataSize> c_data_before{};
    std::memcpy(c_data_before.data(), p.c_data, draughts::kDataSize);
    log_packet_field_set(logger_, "cli_reply_build_response", "c_data", "plaintext_encoded_then_encrypt");
    crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);
    log_crypto_key_usage(logger_,
                         "cli_reply_build_response",
                         "c_data",
                         "encrypt_payload",
                         "响应端长期私钥(identity.sk)",
                         "发起端临时公钥(pk_init_tmp,head=" + pubkey_head(pk_init) + ")",
                         bytes_header_hex(c_data_before.data(), c_data_before.size()),
                         bytes_header_hex(p.c_data, draughts::kDataSize));
    log_packet_snapshot(logger_, "cli_reply_build_response", p);

    log_nh_nnh(logger_,
               peer_label_for(value.addr_ph, value.port_ph),
               peer_label_for(value.addr_nnh, value.port_nnh),
               "cli_reply");

    if (!send_packet_to(p, value.addr_ph, value.port_ph, "cli_reply_send")) {
        console_.println("failed to send reply to out node");
        logger_.warn("cli reply failed");
        return;
    }

    logger_.info("cli send reply outnode=" + endpoint_to_string(value.addr_ph, value.port_ph));
    console_.println("sent reply session=" + sid_hex + " to out node");
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
    logger_.info("收到数据包 from=" + peer_label_for(from.address().to_v4(), from.port()) +
                 " session=" + session_hex_from_packet(p) +
                 " pk_ph_tmp_is_exit=" + std::string(draughts::is_exit_pk(p.pk_ph_tmp) ? "1" : "0"));
    log_packet_cipher_snapshot(logger_, "on_datagram_raw", p);

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
    const std::string sid_hex = session_hex(sid);
    double x = p.params.x;
    logger_.info("处理exit包 session=" + sid_hex + " x=" + std::to_string(x) +
                 " from=" + peer_label_for(from.address().to_v4(), from.port()));
    log_packet_snapshot(logger_, "handle_exit_packet", p);

    if (approx_eq(x, -1.0)) {
        auto it = initiator_sessions_.find(sid);
        if (it != initiator_sessions_.end()) {
            logger_.detail("Session 细节",
                           "stage=exit_reply action=get sid=" + sid_hex +
                           " key=session_id value={resp_peer=" + it->second.resp_peer_id +
                           ",resp_ep=" + endpoint_to_string(it->second.resp_addr, it->second.resp_port) +
                           ",resp_pub_head=" + pubkey_head(it->second.resp_pub) + "}");
            std::string text;
            std::array<std::uint8_t, draughts::kDataSize> tmp{};
            std::memcpy(tmp.data(), p.c_data, draughts::kDataSize);
            auto tmp_before = tmp;
            auto secret = it->second.init_key.DeriveSharedSecret(it->second.resp_pub);
            auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
            crypto::CommutativeCipher::TransformInPlace(tmp.data(), draughts::kDataSize, key_iv.first, key_iv.second);
            log_crypto_key_usage(logger_,
                                 "exit_reply",
                                 "c_data",
                                 "decrypt_payload",
                                 "发起端临时私钥(init_tmp.sk)",
                                 "响应端长期公钥(resp_pub,head=" + pubkey_head(it->second.resp_pub) + ")",
                                 bytes_header_hex(tmp_before.data(), tmp_before.size()),
                                 bytes_header_hex(tmp.data(), tmp.size()));
            if (!decode_payload(tmp.data(), text)) {
                logger_.warn("failed to decrypt response payload");
                return;
            }

            logger_.info("recv reply");
            inbox_.push_back(InboxItem{true, sid_hex, text, ""});
            logger_.info("交付给cli type=reply");
            console_.println("[REPLY] session=" + sid_hex + " text=\"" + text + "\"");
            it->second.last_used_ms = now_ms();
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
        std::array<std::uint8_t, draughts::kDataSize> c_data_before{};
        std::memcpy(c_data_before.data(), p.c_data, draughts::kDataSize);
        crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);
        log_crypto_key_usage(logger_,
                             "exit_request",
                             "c_data",
                             "decrypt_payload",
                             "响应端长期私钥(identity.sk)",
                             "发起端临时公钥(pk_init_tmp,head=" + pubkey_head(pk_init) + ")",
                             bytes_header_hex(c_data_before.data(), c_data_before.size()),
                             bytes_header_hex(p.c_data, draughts::kDataSize));

        std::string text;
        if (!decode_payload(p.c_data, text)) {
            logger_.warn("failed to decode request payload");
            return;
        }

        std::array<std::uint8_t, draughts::kAddrSize> c_addr_real_sender{};
        std::memcpy(c_addr_real_sender.data(), p.params.c_addr_real_sender, draughts::kAddrSize);
        std::uint8_t sender_before[draughts::kAddrSize]{};
        std::memcpy(sender_before, c_addr_real_sender.data(), draughts::kAddrSize);
        if (!transform_real_addr(c_addr_real_sender.data(), identity_, pk_init)) {
            logger_.warn("failed to decrypt c_addr_real_sender at responder");
            return;
        }
        log_addr_transform_detail(logger_,
                                  "exit_request",
                                  "c_addr_real_sender",
                                  "decrypt_at_responder",
                                  "响应端长期私钥(identity.sk)",
                                  "发起端临时公钥(pk_init_tmp,head=" + pubkey_head(pk_init) + ")",
                                  "identity(sk)+pk_init_tmp(head=" + pubkey_head(pk_init) + ")",
                                  sender_before,
                                  c_addr_real_sender.data());

        logger_.info("recv request from=" + endpoint_to_string(from.address().to_v4(), from.port()));
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
        value.topo_term = p.params.topo_term;
        value.created_ms = now_ms();
        responder_lru_.insert_head(sid, value);
        logger_.detail("Session 细节",
                       "stage=exit_request action=store sid=" + sid_hex +
                       " key=session_id value={addr_ph=" + endpoint_to_string(value.addr_ph, value.port_ph) +
                       ",addr_nnh=" + endpoint_to_string(value.addr_nnh, value.port_nnh) +
                       ",pk_pph_tmp_head=" + pubkey_head(value.pk_pph_tmp) +
                       ",pk_init_tmp_head=" + pubkey_head(value.pk_init_tmp) +
                       ",c_addr_real_sender=" + addr_field_readable(value.c_addr_real_sender.data()) +
                       ",topo_term=" + std::to_string(value.topo_term) + "}");

        inbox_.push_back(InboxItem{false, sid_hex, text, endpoint_to_string(from.address().to_v4(), from.port())});
        logger_.info("交付给cli type=request");
        console_.println("[REQUEST] session=" + sid_hex + " from=" + endpoint_to_string(from.address().to_v4(), from.port())
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
        logger_.info("response bootstrap: 响应包首跳下一跳候选=" + peer_label_for(nh_addr, nh_port) +
                     " nh_pub_head=" + pubkey_head(nh_pub));

        // PICK 的排除节点应为当前节点自身，避免把自己选成 NNH。
        std::string exclude_peer_id = cfg_.peer_id;

        std::string nh_peer_id;
        auto nh_desc = node_.lookup_peer_by_draughts_endpoint(nh_addr, nh_port);
        if (nh_desc) nh_peer_id = nh_desc->peer_id;

        address_v4 nnh_addr;
        uint16_t nnh_port = 0;
        draughts::crypto::PubKey nnh_pub{};
        if (!pick_nnh_for_peer_id(nh_peer_id, exclude_peer_id, p.params.topo_term, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh from nh neighbors for response bootstrap");
            return;
        }
        log_packet_field_set(logger_, "response_bootstrap", "params.topo_term", std::to_string(p.params.topo_term));
        log_nh_nnh(logger_,
                   peer_label_for(nh_addr, nh_port),
                   peer_label_for(nnh_addr, nnh_port),
                   "response_bootstrap");

        draughts::crypto::Sm2KeyPair ph_tmp;
        auto ph_pub = ph_tmp.public_key_raw();
        std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);
        log_packet_field_set(logger_, "response_bootstrap", "pk_ph_tmp", pubkey_head(ph_pub));

        // Return-entry behavior: keep c_addr_real_receiver opaque and only add one layer for picked decoy NNH.
        std::uint8_t receiver_before[draughts::kAddrSize]{};
        std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nnh_pub)) {
            logger_.warn("failed to add layer to c_addr_real_receiver at response first hop");
            return;
        }
        log_addr_transform_detail(logger_,
                                  "response_bootstrap",
                                  "c_addr_real_receiver",
                                  "encrypt_for_nnh",
                                  "当前节点临时私钥(ph_tmp.sk)",
                                  "下下跳长期公钥(nnh_pub,head=" + pubkey_head(nnh_pub) + ")",
                                  "ph_tmp(sk)+nnh_pub(head=" + pubkey_head(nnh_pub) + ")",
                                  receiver_before,
                                  p.params.c_addr_real_receiver);

        // Mark first response relay hop as deterministic-continue bootstrap.
        p.params.x = -std::fabs(cfg_.ciplc_x0);
        log_packet_field_set(logger_, "response_bootstrap", "params.x", std::to_string(p.params.x));
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
        log_packet_field_set(logger_, "response_bootstrap", "params.addr_nnh", addr_field_readable(p.params.addr_nnh));

        std::array<std::uint8_t, sizeof(draughts::DraughtsParams)> params_before{};
        std::memcpy(params_before.data(), &p.params, params_before.size());
        if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
            logger_.warn("failed to encrypt response params");
            return;
        }
        log_crypto_key_usage(logger_,
                             "response_bootstrap",
                             "params",
                             "encrypt_for_next_hop",
                             "当前节点临时私钥(ph_tmp.sk)",
                             "下一跳长期公钥(nh_pub,head=" + pubkey_head(nh_pub) + ")",
                             bytes_header_hex(params_before.data(), params_before.size()),
                             bytes_header_hex(reinterpret_cast<const std::uint8_t*>(&p.params),
                                              sizeof(draughts::DraughtsParams)));
        log_packet_cipher_snapshot(logger_, "response_bootstrap", p);

        send_packet_to(p, nh_addr, nh_port, "response_bootstrap_send");
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

    bool response_flow = draughts::is_zero_addr(p.params.c_addr_real_sender);
    bool response_first_hop = response_flow && (p.params.x < 0.0);
    auto from_desc = node_.lookup_peer_by_draughts_endpoint(from.address().to_v4(), from.port());
    std::string from_peer_id = from_desc ? from_desc->peer_id : "";
    logger_.info("随机游走解密后 stage=entry from_peer=" + (from_peer_id.empty() ? "unknown" : from_peer_id) +
                 " response_flow=" + std::string(response_flow ? "1" : "0") +
                 " response_first_hop=" + std::string(response_first_hop ? "1" : "0") +
                 " x=" + std::to_string(p.params.x));
    log_packet_snapshot(logger_, "handle_random_walk_decrypted", p);

    if (approx_eq(p.params.x, 0.0)) {
        if (is_zero_pk_bytes(p.params.pk_pph_tmp) || draughts::is_exit_pk(p.params.pk_pph_tmp)) {
            logger_.warn("invalid pk_pph_tmp for outnode");
            return;
        }
        // Request-phase outnode does not touch c_addr_real_sender; only peel receiver route target.
        if (response_flow) {
            draughts::crypto::PubKey pk_pph{};
            std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
            std::uint8_t receiver_before[draughts::kAddrSize]{};
            std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph)) {
                logger_.warn("failed to peel c_addr_real_receiver at outnode");
                return;
            }
            log_addr_transform_detail(logger_,
                                      "outnode_response",
                                      "c_addr_real_receiver",
                                      "decrypt_with_pk_pph_tmp",
                                      "当前节点长期私钥(identity.sk)",
                                      "前前跳临时公钥(pk_pph_tmp,head=" + pubkey_head(pk_pph) + ")",
                                      "identity(sk)+pk_pph_tmp(head=" + pubkey_head(pk_pph) + ")",
                                      receiver_before,
                                      p.params.c_addr_real_receiver);
        } else {
            draughts::crypto::PubKey pk_pph{};
            std::memcpy(pk_pph.data(), p.params.pk_pph_tmp, draughts::kPkSize);
            std::uint8_t receiver_before[draughts::kAddrSize]{};
            std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);
            if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph)) {
                logger_.warn("failed to peel c_addr_real_receiver at outnode");
                return;
            }
            log_addr_transform_detail(logger_,
                                      "outnode_request",
                                      "c_addr_real_receiver",
                                      "decrypt_with_pk_pph_tmp",
                                      "当前节点长期私钥(identity.sk)",
                                      "前前跳临时公钥(pk_pph_tmp,head=" + pubkey_head(pk_pph) + ")",
                                      "identity(sk)+pk_pph_tmp(head=" + pubkey_head(pk_pph) + ")",
                                      receiver_before,
                                      p.params.c_addr_real_receiver);
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
        log_nh_nnh(logger_,
                   peer_label_for(responder_addr, responder_port),
                   "直连交付",
                   "outnode_deliver");

        std::memcpy(p.params.pk_pph_tmp, p.pk_ph_tmp, draughts::kPkSize);
        log_packet_field_set(logger_, "outnode_deliver", "params.pk_pph_tmp", pk_field_head(p.params.pk_pph_tmp));
        p.params.x = -1.0;
        log_packet_field_set(logger_, "outnode_deliver", "params.x", "-1.0");
        draughts::fill_exit_pk(p.pk_ph_tmp);
        log_packet_field_set(logger_, "outnode_deliver", "pk_ph_tmp", "EXIT_MARK(0xEE)");
        log_packet_snapshot(logger_, "outnode_deliver", p);
        send_packet_to(p, responder_addr, responder_port, "outnode_deliver");
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
    bool request_initial_stage = false;
    bool response_bootstrap_stage = false;
    double x_before = p.params.x;
    if (response_flow) {
        do_continue = response_first_hop;
        if (response_first_hop) {
            response_bootstrap_stage = true;
            Ciplc ciplc = ciplc_;
            ciplc.x = std::fabs(p.params.x);
            (void)ciplc.step_and_decide(rng_);
            // Keep response bootstrap marker one-shot: next hop should not be treated as first hop again.
            p.params.x = std::fabs(ciplc.x);
        }
    } else {
        Ciplc ciplc = ciplc_;
        ciplc.x = p.params.x;
        request_initial_stage = approx_eq(p.params.x, cfg_.ciplc_x0);
        bool mapped_continue = ciplc.step_and_decide(rng_);
        p.params.x = ciplc.x;
        // Initial request stage always continues path expansion while still updating x.
        do_continue = can_continue && (request_initial_stage || mapped_continue);
    }
    logger_.info("随机游走决策 can_continue=" + std::string(can_continue ? "1" : "0") +
                 " do_continue=" + std::string(do_continue ? "1" : "0") +
                 " request_initial_stage=" + std::string(request_initial_stage ? "1" : "0") +
                 " response_bootstrap_stage=" + std::string(response_bootstrap_stage ? "1" : "0") +
                 " x_before=" + std::to_string(x_before) +
                 " x_after=" + std::to_string(p.params.x));

    // PICK 的排除节点应为当前节点自身，避免把自己选成 NNH。
    std::string exclude_peer_id = cfg_.peer_id;

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
        if (!pick_nnh_for_peer_id(nh_peer_id, exclude_peer_id, p.params.topo_term, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh for relay");
            return;
        }
        log_packet_field_set(logger_,
                             response_flow ? "response_continue" : "relay_continue",
                             "params.topo_term",
                             std::to_string(p.params.topo_term));
        auto nnh_desc = node_.lookup_peer_by_draughts_endpoint(nnh_addr, nnh_port);
        std::string nnh_peer_id = nnh_desc ? nnh_desc->peer_id : "";
        (void)nnh_peer_id;

        log_nh_nnh(logger_,
                   peer_label_for(nh_addr, nh_port),
                   peer_label_for(nnh_addr, nnh_port),
                   response_flow ? "response_continue" : "request_continue");

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

        const char* flow_stage = response_flow ? "response_continue" : "relay_continue";
        std::uint8_t receiver_before_peel[draughts::kAddrSize]{};
        std::memcpy(receiver_before_peel, p.params.c_addr_real_receiver, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph)) {
            logger_.warn("failed to peel c_addr_real_receiver at relay");
            return;
        }
        log_addr_transform_detail(logger_,
                                  flow_stage,
                                  "c_addr_real_receiver",
                                  "decrypt_with_pk_pph_tmp",
                                  "当前节点长期私钥(identity.sk)",
                                  "前前跳临时公钥(pk_pph_tmp,head=" + pubkey_head(pk_pph) + ")",
                                  "identity(sk)+pk_pph_tmp(head=" + pubkey_head(pk_pph) + ")",
                                  receiver_before_peel,
                                  p.params.c_addr_real_receiver);

        std::uint8_t receiver_before_add[draughts::kAddrSize]{};
        std::memcpy(receiver_before_add, p.params.c_addr_real_receiver, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nnh_pub)) {
            logger_.warn("failed to add layer to c_addr_real_receiver at relay");
            return;
        }
        log_addr_transform_detail(logger_,
                                  flow_stage,
                                  "c_addr_real_receiver",
                                  "encrypt_for_nnh",
                                  "当前节点临时私钥(ph_tmp.sk)",
                                  "下下跳长期公钥(nnh_pub,head=" + pubkey_head(nnh_pub) + ")",
                                  "ph_tmp(sk)+nnh_pub(head=" + pubkey_head(nnh_pub) + ")",
                                  receiver_before_add,
                                  p.params.c_addr_real_receiver);
        std::memcpy(p.params.pk_pph_tmp, old_ph.data(), draughts::kPkSize);
        log_packet_field_set(logger_, std::string(flow_stage), "params.pk_pph_tmp", pk_field_head(p.params.pk_pph_tmp));
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
        log_packet_field_set(logger_, std::string(flow_stage), "params.addr_nnh", addr_field_readable(p.params.addr_nnh));

        std::array<std::uint8_t, sizeof(draughts::DraughtsParams)> params_before{};
        std::memcpy(params_before.data(), &p.params, params_before.size());
        if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
            logger_.warn("failed to encrypt params for relay");
            return;
        }
        log_crypto_key_usage(logger_,
                             flow_stage,
                             "params",
                             "encrypt_for_next_hop",
                             "当前节点临时私钥(ph_tmp.sk)",
                             "下一跳长期公钥(nh_pub,head=" + pubkey_head(nh_pub) + ")",
                             bytes_header_hex(params_before.data(), params_before.size()),
                             bytes_header_hex(reinterpret_cast<const std::uint8_t*>(&p.params),
                                              sizeof(draughts::DraughtsParams)));
        log_packet_cipher_snapshot(logger_, std::string(flow_stage), p);

        send_packet_to(p, nh_addr, nh_port, std::string(flow_stage) + "_send");
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
        logger_.warn("outnode selection failed from addr_nnh; dropping");
        return;
    }
    if (outnode_port == 0) {
        logger_.warn("outnode port missing");
        return;
    }

    address_v4 nnh_addr;
    uint16_t nnh_port = 0;
    draughts::crypto::PubKey nnh_pub{};
    if (!response_flow) {
        if (!pick_nnh_for_peer_id(outnode_peer_id, exclude_peer_id, p.params.topo_term, nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("failed to pick nnh from outnode neighbors for outnode leg");
            return;
        }
        log_packet_field_set(logger_, "outnode_exit", "params.topo_term", std::to_string(p.params.topo_term));
    }

    log_nh_nnh(logger_,
               peer_label_for(outnode_addr, outnode_port),
               response_flow ? "无需下下跳" : peer_label_for(nnh_addr, nnh_port),
               response_flow ? "response_outnode" : "request_outnode");

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
        std::uint8_t receiver_before[draughts::kAddrSize]{};
        std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph)) {
            logger_.warn("failed to peel c_addr_real_receiver at response exit");
            return;
        }
        log_addr_transform_detail(logger_,
                                  "outnode_exit_response",
                                  "c_addr_real_receiver",
                                  "decrypt_with_pk_pph_tmp",
                                  "当前节点长期私钥(identity.sk)",
                                  "前前跳临时公钥(pk_pph_tmp,head=" + pubkey_head(pk_pph) + ")",
                                  "identity(sk)+pk_pph_tmp(head=" + pubkey_head(pk_pph) + ")",
                                  receiver_before,
                                  p.params.c_addr_real_receiver);
    } else {
        std::uint8_t receiver_before[draughts::kAddrSize]{};
        std::memcpy(receiver_before, p.params.c_addr_real_receiver, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_receiver, identity_, pk_pph)) {
            logger_.warn("failed to peel c_addr_real_receiver at exit");
            return;
        }
        log_addr_transform_detail(logger_,
                                  "outnode_exit_request",
                                  "c_addr_real_receiver",
                                  "decrypt_with_pk_pph_tmp",
                                  "当前节点长期私钥(identity.sk)",
                                  "前前跳临时公钥(pk_pph_tmp,head=" + pubkey_head(pk_pph) + ")",
                                  "identity(sk)+pk_pph_tmp(head=" + pubkey_head(pk_pph) + ")",
                                  receiver_before,
                                  p.params.c_addr_real_receiver);

        std::uint8_t sender_before[draughts::kAddrSize]{};
        std::memcpy(sender_before, p.params.c_addr_real_sender, draughts::kAddrSize);
        if (!transform_real_addr(p.params.c_addr_real_sender, ph_tmp, nnh_pub)) {
            logger_.warn("failed to add layer to c_addr_real_sender at exit (request)");
            return;
        }
        log_addr_transform_detail(logger_,
                                  "outnode_exit_request",
                                  "c_addr_real_sender",
                                  "encrypt_for_nnh",
                                  "当前节点临时私钥(ph_tmp.sk)",
                                  "下下跳长期公钥(nnh_pub,head=" + pubkey_head(nnh_pub) + ")",
                                  "ph_tmp(sk)+nnh_pub(head=" + pubkey_head(nnh_pub) + ")",
                                  sender_before,
                                  p.params.c_addr_real_sender);
    }

    p.params.x = 0.0;
    log_packet_field_set(logger_, "outnode_exit", "params.x", "0.0");
    if (!response_flow) {
        addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
        log_packet_field_set(logger_, "outnode_exit", "params.addr_nnh", addr_field_readable(p.params.addr_nnh));
    } else {
        draughts::zero_addr(p.params.addr_nnh);
        log_packet_field_set(logger_, "outnode_exit", "params.addr_nnh", addr_field_readable(p.params.addr_nnh));
    }

    std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "outnode_exit", "pk_ph_tmp", pubkey_head(ph_pub));
    std::memcpy(p.params.pk_pph_tmp, prev_ph.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "outnode_exit", "params.pk_pph_tmp", pk_field_head(p.params.pk_pph_tmp));

    std::array<std::uint8_t, sizeof(draughts::DraughtsParams)> params_before{};
    std::memcpy(params_before.data(), &p.params, params_before.size());
    if (!encrypt_params_for_next_hop(p, outnode_pub, ph_tmp)) {
        logger_.warn("failed to encrypt params for outnode");
        return;
    }
    log_crypto_key_usage(logger_,
                         "outnode_exit",
                         "params",
                         "encrypt_for_next_hop",
                         "当前节点临时私钥(ph_tmp.sk)",
                         "outnode长期公钥(outnode_pub,head=" + pubkey_head(outnode_pub) + ")",
                         bytes_header_hex(params_before.data(), params_before.size()),
                         bytes_header_hex(reinterpret_cast<const std::uint8_t*>(&p.params),
                                          sizeof(draughts::DraughtsParams)));
    log_packet_cipher_snapshot(logger_, "outnode_exit", p);

    send_packet_to(p, outnode_addr, outnode_port, "outnode_exit_send");
}

bool DraughtsApp::decrypt_params(draughts::DraughtsPacket& p) {
    draughts::crypto::PubKey pk_ph{};
    std::memcpy(pk_ph.data(), p.pk_ph_tmp, draughts::kPkSize);
    auto secret = identity_.DeriveSharedSecret(pk_ph);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);

    auto* params_bytes = reinterpret_cast<std::uint8_t*>(&p.params);
    std::array<std::uint8_t, sizeof(draughts::DraughtsParams)> params_before{};
    std::memcpy(params_before.data(), params_bytes, params_before.size());
    crypto::CommutativeCipher::TransformInPlace(params_bytes, sizeof(draughts::DraughtsParams), key_iv.first, key_iv.second);
    log_crypto_key_usage(logger_,
                         "decrypt_params",
                         "params",
                         "decrypt_by_pk_ph_tmp",
                         "当前节点长期私钥(identity.sk)",
                         "前跳临时公钥(pk_ph_tmp,head=" + pubkey_head(pk_ph) + ")",
                         bytes_header_hex(params_before.data(), params_before.size()),
                         bytes_header_hex(params_bytes, sizeof(draughts::DraughtsParams)));
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
                                 uint16_t port,
                                 const std::string& stage) {
    if (port == 0) return false;
    udp::endpoint ep(addr, port);
    auto buf = std::make_shared<std::array<uint8_t, draughts::kPacketSize>>();
    std::memcpy(buf->data(), &p, draughts::kPacketSize);
    std::string suffix;
    if (!stage.empty()) suffix = " stage=" + stage;
    logger_.info("转发数据包给" + peer_label_for(addr, port) + suffix +
                 " session=" + session_hex_from_packet(p));
    sock_.async_send_to(boost::asio::buffer(*buf), ep, [buf](auto, auto) {});
    return true;
}

std::string DraughtsApp::peer_label_for(const address_v4& addr, uint16_t port) const {
    auto desc = node_.lookup_peer_by_draughts_endpoint(addr, port);
    auto ep = endpoint_to_string(addr, port);
    if (desc && !desc->peer_id.empty()) {
        return desc->peer_id + "@" + ep;
    }
    if (port == cfg_.draughts_port) {
        boost::system::error_code ec;
        auto self_addr = address_v4::from_string(cfg_.bind_ip, ec);
        if (!ec && self_addr == addr && !cfg_.peer_id.empty()) {
            return cfg_.peer_id + "@" + ep;
        }
    }
    return ep;
}

bool DraughtsApp::transform_real_addr(std::uint8_t addr[draughts::kAddrSize],
                                      const draughts::crypto::Sm2KeyPair& priv_key,
                                      const draughts::crypto::PubKey& peer_pub) {
    return transform_addr_layer(addr, priv_key, peer_pub);
}

bool DraughtsApp::pick_nh_nnh(address_v4& nh_addr,
                              uint16_t& nh_port,
                              draughts::crypto::PubKey& nh_pub,
                              address_v4& nnh_addr,
                              uint16_t& nnh_port,
                              draughts::crypto::PubKey& nnh_pub,
    std::uint64_t& topo_term,
    const std::string& exclude_peer_id) {
    topo_term = 0;
    if (!topod_.enabled()) {
        logger_.warn("topod disabled; static topology compatibility is removed");
        return false;
    }
    logger_.info("开始选择路由 stage=pick_nh_nnh exclude_peer_id=" + (exclude_peer_id.empty() ? "none" : exclude_peer_id));
    TopodClient::RoutePlan plan{};
    if (!topod_.pick_route(exclude_peer_id, plan)) {
        logger_.warn("topod PLAN query failed");
        return false;
    }
    nh_addr = plan.nh.addr;
    nh_port = plan.nh.port;
    nh_pub = plan.nh.pubkey;
    nnh_addr = plan.nnh.addr;
    nnh_port = plan.nnh.port;
    nnh_pub = plan.nnh.pubkey;
    topo_term = plan.term;
    node_.cache_twohop_neighbor(plan.nh.peer_id, plan.nnh.peer_id);
    logger_.info("路由选择完成 topo_term=" + std::to_string(topo_term) +
                 " nh=" + plan.nh.peer_id + "@" + endpoint_to_string(nh_addr, nh_port) +
                 " nnh=" + plan.nnh.peer_id + "@" + endpoint_to_string(nnh_addr, nnh_port) +
                 " nh_pub_head=" + pubkey_head(nh_pub) +
                 " nnh_pub_head=" + pubkey_head(nnh_pub));
    return true;
}

bool DraughtsApp::pick_nnh_for_peer_id(const std::string& nh_peer_id,
                                       const std::string& exclude_peer_id,
    std::uint64_t& topo_term,
    address_v4& nnh_addr,
    uint16_t& nnh_port,
    draughts::crypto::PubKey& nnh_pub) {
    if (!topod_.enabled()) {
        logger_.warn("topod disabled; cannot pick nnh via PICK");
        return false;
    }
    if (nh_peer_id.empty() || topo_term == 0) {
        logger_.warn("invalid inputs for topod PICK nnh query");
        return false;
    }
    std::string nh_label = nh_peer_id;
    if (auto nh_desc = node_.lookup_peer(nh_peer_id); nh_desc && nh_desc->draughts_port != 0) {
        nh_label = nh_desc->peer_id + "@" + endpoint_to_string(addr_from_bytes(nh_desc->ip), nh_desc->draughts_port);
    }
    logger_.info("根据下一跳" + nh_label + "选择下下跳 term=" + std::to_string(topo_term) +
                 " exclude=" + (exclude_peer_id.empty() ? "none" : exclude_peer_id));
    TopodClient::HopInfo nnh{};
    std::uint64_t resolved_term = topo_term;
    bool ok = topod_.pick_pick_nnh(nh_peer_id, topo_term, exclude_peer_id, resolved_term, nnh);
    if (!ok) {
        logger_.warn("topod PICK nnh query failed (strict-only mode), fallback to node twohop/active cache");
        auto fallback_nnh_id = node_.pick_nnh_for(nh_peer_id, exclude_peer_id, false);
        if (!fallback_nnh_id) {
            logger_.warn("fallback nnh pick failed: no candidate in node cache");
            return false;
        }
        auto fallback_desc = node_.lookup_peer(*fallback_nnh_id);
        if (!fallback_desc || fallback_desc->draughts_port == 0) {
            logger_.warn("fallback nnh pick failed: peer descriptor missing for " + *fallback_nnh_id);
            return false;
        }
        nnh_addr = addr_from_bytes(fallback_desc->ip);
        nnh_port = fallback_desc->draughts_port;
        if (!get_peer_pubkey_by_endpoint(nnh_addr, nnh_port, nnh_pub)) {
            logger_.warn("fallback nnh pick failed: pubkey missing for " + *fallback_nnh_id);
            return false;
        }
        node_.cache_twohop_neighbor(nh_peer_id, *fallback_nnh_id);
        // PICK 失败时没有新的 term，保持来包 term 不变。
        logger_.info("根据下一跳" + nh_label + "回退选择下下跳结果=" + *fallback_nnh_id + "@" +
                     endpoint_to_string(nnh_addr, nnh_port) +
                     " nnh_pub_head=" + pubkey_head(nnh_pub));
        return true;
    }
    topo_term = resolved_term;
    nnh_addr = nnh.addr;
    nnh_port = nnh.port;
    nnh_pub = nnh.pubkey;
    node_.cache_twohop_neighbor(nh_peer_id, nnh.peer_id);
    logger_.info("根据下一跳" + nh_label + "选择下下跳结果=" + nnh.peer_id + "@" +
                 endpoint_to_string(nnh_addr, nnh_port) +
                 " nnh_pub_head=" + pubkey_head(nnh_pub));
    return true;
}

std::string DraughtsApp::session_hex(const std::string& sid) {
    return bytes_to_hex(reinterpret_cast<const uint8_t*>(sid.data()), sid.size());
}

bool DraughtsApp::parse_session_hex(const std::string& session_hex_in, std::string& sid) {
    if (session_hex_in.size() != draughts::kSessionIdSize * 2) return false;
    if (session_hex_in.size() % 2 != 0) return false;
    sid.resize(session_hex_in.size() / 2);
    try {
        for (size_t i = 0; i < session_hex_in.size(); i += 2) {
            auto byte = std::stoi(session_hex_in.substr(i, 2), nullptr, 16);
            sid[i / 2] = static_cast<char>(byte & 0xFF);
        }
    } catch (...) {
        return false;
    }
    return true;
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
    logger_.detail("Route 细节",
                   "stage=get_peer_pubkey_by_endpoint ep=" + endpoint_to_string(addr, port) +
                   " pub_head=" + pubkey_head(out_pubkey));
    return true;
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

bool DraughtsApp::send_request_with_session(const std::string& sid,
                                            InitiatorSession& session,
                                            const std::string& text) {
    address_v4 nh_addr;
    uint16_t nh_port = 0;
    draughts::crypto::PubKey nh_pub{};
    address_v4 nnh_addr;
    uint16_t nnh_port = 0;
    draughts::crypto::PubKey nnh_pub{};
    std::uint64_t topo_term = 0;
    if (!pick_nh_nnh(nh_addr, nh_port, nh_pub, nnh_addr, nnh_port, nnh_pub, topo_term, "")) {
        console_.println("no active neighbors to start random walk");
        logger_.warn("cli send failed: no active neighbors");
        return false;
    }
    logger_.detail("Session 细节",
                   "stage=send_request_with_session action=get sid=" + session_hex(sid) +
                   " key=session_id value={resp_peer=" + session.resp_peer_id +
                   ",resp_ep=" + endpoint_to_string(session.resp_addr, session.resp_port) +
                   ",resp_pub_head=" + pubkey_head(session.resp_pub) + "}");

    const std::string sid_hex = session_hex(sid);

    draughts::DraughtsPacket p{};
    log_packet_construct(logger_, "cli_request_build_packet", sid_hex, "request");
    std::memcpy(p.session_id, sid.data(), draughts::kSessionIdSize);
    log_packet_field_set(logger_, "cli_request_build_packet", "session_id", sid_hex);

    draughts::crypto::Sm2KeyPair ph_tmp;
    auto ph_pub = ph_tmp.public_key_raw();
    std::memcpy(p.pk_ph_tmp, ph_pub.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "cli_request_build_packet", "pk_ph_tmp", pubkey_head(ph_pub));
    std::memcpy(p.params.pk_pph_tmp, ph_pub.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "cli_request_build_packet", "params.pk_pph_tmp", pk_field_head(p.params.pk_pph_tmp));

    auto init_pub = session.init_key.public_key_raw();
    std::memcpy(p.params.pk_init_tmp, init_pub.data(), draughts::kPkSize);
    log_packet_field_set(logger_, "cli_request_build_packet", "params.pk_init_tmp", pubkey_head(init_pub));

    addr_to_bytes(nnh_addr, nnh_port, p.params.addr_nnh);
    log_packet_field_set(logger_, "cli_request_build_packet", "params.addr_nnh", addr_field_readable(p.params.addr_nnh));
    addr_to_bytes(session.resp_addr, session.resp_port, p.params.c_addr_real_receiver);
    log_packet_field_set(logger_, "cli_request_build_packet", "params.c_addr_real_receiver", addr_field_readable(p.params.c_addr_real_receiver));
    addr_to_bytes(address_v4::from_string(cfg_.bind_ip), cfg_.draughts_port, p.params.c_addr_real_sender);
    log_packet_field_set(logger_, "cli_request_build_packet", "params.c_addr_real_sender", addr_field_readable(p.params.c_addr_real_sender));

    std::uint8_t before_receiver_1[draughts::kAddrSize]{};
    std::memcpy(before_receiver_1, p.params.c_addr_real_receiver, draughts::kAddrSize);
    if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nh_pub)) {
        console_.println("failed to wrap c_addr_real_receiver for first hop");
        logger_.warn("cli send failed: wrap c_addr_real_receiver (nh)");
        return false;
    }
    log_addr_transform_detail(logger_,
                              "cli_request",
                              "c_addr_real_receiver",
                              "encrypt_for_nh",
                              "当前节点临时私钥(ph_tmp.sk)",
                              "下一跳长期公钥(nh_pub,head=" + pubkey_head(nh_pub) + ")",
                              "ph_tmp(sk)+nh_pub(head=" + pubkey_head(nh_pub) + ")",
                              before_receiver_1,
                              p.params.c_addr_real_receiver);

    std::uint8_t before_receiver_2[draughts::kAddrSize]{};
    std::memcpy(before_receiver_2, p.params.c_addr_real_receiver, draughts::kAddrSize);
    if (!transform_real_addr(p.params.c_addr_real_receiver, ph_tmp, nnh_pub)) {
        console_.println("failed to wrap c_addr_real_receiver for second hop");
        logger_.warn("cli send failed: wrap c_addr_real_receiver (nnh)");
        return false;
    }
    log_addr_transform_detail(logger_,
                              "cli_request",
                              "c_addr_real_receiver",
                              "encrypt_for_nnh",
                              "当前节点临时私钥(ph_tmp.sk)",
                              "下下跳长期公钥(nnh_pub,head=" + pubkey_head(nnh_pub) + ")",
                              "ph_tmp(sk)+nnh_pub(head=" + pubkey_head(nnh_pub) + ")",
                              before_receiver_2,
                              p.params.c_addr_real_receiver);

    std::uint8_t before_sender[draughts::kAddrSize]{};
    std::memcpy(before_sender, p.params.c_addr_real_sender, draughts::kAddrSize);
    if (!transform_real_addr(p.params.c_addr_real_sender, session.init_key, session.resp_pub)) {
        console_.println("failed to wrap c_addr_real_sender for responder");
        logger_.warn("cli send failed: wrap c_addr_real_sender");
        return false;
    }
    log_addr_transform_detail(logger_,
                              "cli_request",
                              "c_addr_real_sender",
                              "encrypt_for_responder",
                              "发起端临时私钥(init_tmp.sk)",
                              "响应端长期公钥(resp_pub,head=" + pubkey_head(session.resp_pub) + ")",
                              "init_tmp(sk)+resp_pub(head=" + pubkey_head(session.resp_pub) + ")",
                              before_sender,
                              p.params.c_addr_real_sender);

    p.params.x = cfg_.ciplc_x0;
    log_packet_field_set(logger_, "cli_request_build_packet", "params.x", std::to_string(p.params.x));
    p.params.topo_term = topo_term;
    log_packet_field_set(logger_, "cli_request_build_packet", "params.topo_term", std::to_string(topo_term));
    p.params.magic_num = cfg_.magic_num;
    log_packet_field_set(logger_, "cli_request_build_packet", "params.magic_num", "0x" + hex_bytes(reinterpret_cast<const std::uint8_t*>(&cfg_.magic_num), sizeof(cfg_.magic_num)));

    std::uint8_t pt[draughts::kDataSize] = {};
    encode_payload(text, pt);

    auto secret = session.init_key.DeriveSharedSecret(session.resp_pub);
    auto key_iv = draughts::crypto::Sm2KeyPair::DeriveKeyAndIv(secret);
    std::memcpy(p.c_data, pt, draughts::kDataSize);
    std::array<std::uint8_t, draughts::kDataSize> c_data_before{};
    std::memcpy(c_data_before.data(), p.c_data, draughts::kDataSize);
    log_packet_field_set(logger_, "cli_request_build_packet", "c_data", "plaintext_encoded_then_encrypt");
    crypto::CommutativeCipher::TransformInPlace(p.c_data, draughts::kDataSize, key_iv.first, key_iv.second);
    log_crypto_key_usage(logger_,
                         "cli_request",
                         "c_data",
                         "encrypt_payload",
                         "发起端临时私钥(init_tmp.sk)",
                         "响应端长期公钥(resp_pub,head=" + pubkey_head(session.resp_pub) + ")",
                         bytes_header_hex(c_data_before.data(), c_data_before.size()),
                         bytes_header_hex(p.c_data, draughts::kDataSize));

    std::array<std::uint8_t, sizeof(draughts::DraughtsParams)> params_before{};
    std::memcpy(params_before.data(), &p.params, params_before.size());
    if (!encrypt_params_for_next_hop(p, nh_pub, ph_tmp)) {
        console_.println("failed to encrypt params for first hop");
        logger_.warn("cli send failed: encrypt params");
        return false;
    }
    log_crypto_key_usage(logger_,
                         "cli_request",
                         "params",
                         "encrypt_for_first_hop",
                         "当前节点临时私钥(ph_tmp.sk)",
                         "下一跳长期公钥(nh_pub,head=" + pubkey_head(nh_pub) + ")",
                         bytes_header_hex(params_before.data(), params_before.size()),
                         bytes_header_hex(reinterpret_cast<const std::uint8_t*>(&p.params),
                                          sizeof(draughts::DraughtsParams)));
    log_packet_cipher_snapshot(logger_, "cli_request_ready_to_send", p);

    logger_.info("cli send request responder=" + peer_label_for(session.resp_addr, session.resp_port) +
                 " nh=" + peer_label_for(nh_addr, nh_port) +
                 " nnh=" + peer_label_for(nnh_addr, nnh_port) +
                 " topo_term=" + std::to_string(topo_term));

    if (!send_packet_to(p, nh_addr, nh_port, "cli_request_send")) {
        console_.println("failed to send packet to next hop");
        logger_.warn("cli send failed");
        return false;
    }

    session.last_used_ms = now_ms();
    console_.println("sent session=" + sid_hex +
                     " to responder=" + endpoint_to_string(session.resp_addr, session.resp_port));
    return true;
}

void DraughtsApp::prune_sessions() {
    uint64_t now = now_ms();
    for (auto it = initiator_sessions_.begin(); it != initiator_sessions_.end(); ) {
        if (now - it->second.last_used_ms > cfg_.session_ttl_ms) {
            logger_.detail("Session 细节",
                           "stage=prune_sessions action=erase sid=" + session_hex(it->first) +
                           " reason=ttl_expired ttl_ms=" + std::to_string(cfg_.session_ttl_ms) +
                           " idle_ms=" + std::to_string(now - it->second.last_used_ms));
            initiator_session_ids_.erase(it->first);
            it = initiator_sessions_.erase(it);
        } else {
            ++it;
        }
    }
}
