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
    std::vector<std::string> bootstraps; // "ipv4:overlay_port:draughts_port"

    // Logging
    std::string log_file = "draughts.log";
    std::string log_level = "info";
    bool cli_enabled = true;
    std::string active_neighbors_file;

    // HyParView view sizes
    size_t active_min = 4;
    size_t active_max = 8;
    size_t passive_max = 80;

    // HyParView timers
    uint32_t lease_ms = 30000;
    uint32_t keepalive_every_ms = 10000;
    uint32_t shuffle_every_ms = 12000;
    uint32_t repair_every_ms = 2000;

    // HyParView parameters
    uint16_t join_ttl = 4;
    size_t shuffle_k = 8;

    // Two-hop neighbor maintenance
    uint32_t neighbor_set_every_ms = 5000;
    size_t neighbor_set_k = 8;

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

    // App packet padding (0 disables). Recommended: <= 1280 for draughts data.
    size_t app_pad_to = 0;
};

bool load_config(const std::string& path, Config& out, std::string& err);
