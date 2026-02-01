#include "config.hpp"

#include "util.hpp"

#include <fstream>
#include <sstream>

namespace {

bool parse_bool(const std::string& s, bool& out) {
    if (s == "1" || s == "true" || s == "yes" || s == "on") { out = true; return true; }
    if (s == "0" || s == "false" || s == "no" || s == "off") { out = false; return true; }
    return false;
}

} // namespace

bool load_config(const std::string& path, Config& out, std::string& err) {
    std::ifstream in(path);
    if (!in.is_open()) {
        err = "failed to open config: " + path;
        return false;
    }

    std::string line;
    size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) {
            err = "bad config line " + std::to_string(lineno) + ": missing '='";
            return false;
        }
        std::string key = trim(line.substr(0, pos));
        std::string val = trim(line.substr(pos + 1));
        if (key.empty()) continue;

        try {
            if (key == "peer_id") out.peer_id = val;
            else if (key == "bind_ip") out.bind_ip = val;
            else if (key == "overlay_port") out.overlay_port = static_cast<uint16_t>(std::stoul(val));
            else if (key == "draughts_port") out.draughts_port = static_cast<uint16_t>(std::stoul(val));
            else if (key == "bootstrap") out.bootstraps.push_back(val);
            else if (key == "bootstraps") {
                std::stringstream ss(val);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    item = trim(item);
                    if (!item.empty()) out.bootstraps.push_back(item);
                }
            }
            else if (key == "log_file") out.log_file = val;
            else if (key == "log_level") out.log_level = val;
            else if (key == "cli_enabled") {
                bool b = false;
                if (!parse_bool(val, b)) {
                    err = "bad config value at line " + std::to_string(lineno) + ": invalid bool";
                    return false;
                }
                out.cli_enabled = b;
            }
            else if (key == "active_neighbors_file") out.active_neighbors_file = val;
            else if (key == "self_info_file") out.self_info_file = val;
            else if (key == "peer_info_dir") out.peer_info_dir = val;
            else if (key == "identity_key_file") out.identity_key_file = val;
            else if (key == "static_topology") {
                bool b = false;
                if (!parse_bool(val, b)) {
                    err = "bad config value at line " + std::to_string(lineno) + ": invalid bool";
                    return false;
                }
                out.static_topology = b;
            }
            else if (key == "topology_dir") out.topology_dir = val;

            else if (key == "active_min") out.active_min = static_cast<size_t>(std::stoul(val));
            else if (key == "active_max") out.active_max = static_cast<size_t>(std::stoul(val));
            else if (key == "passive_max") out.passive_max = static_cast<size_t>(std::stoul(val));

            else if (key == "lease_ms") out.lease_ms = static_cast<uint32_t>(std::stoul(val));
            else if (key == "keepalive_every_ms") out.keepalive_every_ms = static_cast<uint32_t>(std::stoul(val));
            else if (key == "shuffle_every_ms") out.shuffle_every_ms = static_cast<uint32_t>(std::stoul(val));
            else if (key == "repair_every_ms") out.repair_every_ms = static_cast<uint32_t>(std::stoul(val));

            else if (key == "join_ttl") out.join_ttl = static_cast<uint16_t>(std::stoul(val));
            else if (key == "shuffle_k") out.shuffle_k = static_cast<size_t>(std::stoul(val));

            else if (key == "neighbor_set_every_ms") out.neighbor_set_every_ms = static_cast<uint32_t>(std::stoul(val));
            else if (key == "neighbor_set_k") out.neighbor_set_k = static_cast<size_t>(std::stoul(val));

            else if (key == "ciplc_a") out.ciplc_a = std::stod(val);
            else if (key == "ciplc_b") out.ciplc_b = std::stod(val);
            else if (key == "ciplc_c") out.ciplc_c = std::stod(val);
            else if (key == "ciplc_epsilon") out.ciplc_epsilon = std::stod(val);
            else if (key == "ciplc_x0") out.ciplc_x0 = std::stod(val);

            else if (key == "magic_num") out.magic_num = static_cast<uint64_t>(std::stoull(val, nullptr, 0));
            else if (key == "session_ttl_ms") out.session_ttl_ms = static_cast<uint32_t>(std::stoul(val));
            else if (key == "outnode_ttl_ms") out.outnode_ttl_ms = static_cast<uint32_t>(std::stoul(val));

            else if (key == "app_pad_to") out.app_pad_to = static_cast<size_t>(std::stoul(val));
            else {
                err = "unknown config key at line " + std::to_string(lineno) + ": " + key;
                return false;
            }
        } catch (const std::exception& e) {
            err = "bad config value at line " + std::to_string(lineno) + ": " + e.what();
            return false;
        }
    }

    return true;
}
