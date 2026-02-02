#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct Config {
    // Identity / network
    std::string peer_id = "node";
    std::string bind_ip = "0.0.0.0"; // IPv4
    uint16_t overlay_port = 0;
    uint16_t draughts_port = 0;

    // Logging
    std::string log_file = "draughts.log";
    std::string log_level = "info";
    bool cli_enabled = true;
    std::string active_neighbors_file;
    std::string self_info_file;
    std::string peer_info_dir;
    std::string identity_key_file;
    std::string topology_dir;

    // Static topology degree expectations
    size_t active_min = 4;
    size_t active_max = 8;

    // CIPLC parameters
    double ciplc_a = 1.0;
    double ciplc_b = 0.1;
    double ciplc_c = 3.0;
    double ciplc_epsilon = 0.008;
    double ciplc_x0 = 0.03;

    // Draughts protocol
    uint64_t magic_num = 0x4452415547485453ull; // "DRAUGHTS"
    uint32_t session_ttl_ms = 300000;
    uint32_t outnode_ttl_ms = 300000;

};

bool load_config(const std::string& path, Config& out, std::string& err);
