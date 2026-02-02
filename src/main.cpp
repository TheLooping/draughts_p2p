#include <boost/asio.hpp>

#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include "base64.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "console.hpp"
#include "crypto/Crypto.h"
#include "draughts_app.hpp"
#include "io_layer.hpp"
#include "logger.hpp"
#include "overlay.hpp"

namespace {

void usage(const char* argv0) {
    std::cout << "Usage:\n";
    std::cout << "  " << argv0 << " <config_path>\n";
}

LogLevel parse_level(const std::string& s) {
    if (s == "debug") return LogLevel::DEBUG;
    if (s == "info") return LogLevel::INFO;
    if (s == "warn") return LogLevel::WARN;
    if (s == "error") return LogLevel::ERROR;
    return LogLevel::INFO;
}

} // namespace

int main(int argc, char** argv) {
    std::string cfg_path = "./config/default.conf";
    if (argc == 2) {
        cfg_path = argv[1];
    } else if (argc > 2) {
        usage(argv[0]);
        return 2;
    }

    Config cfg;
    std::string err;
    if (!load_config(cfg_path, cfg, err)) {
        std::cerr << err << "\n";
        return 2;
    }
    if (cfg.overlay_port == 0 || cfg.draughts_port == 0) {
        std::cerr << "overlay_port and draughts_port must be set (non-zero)\n";
        return 2;
    }
    boost::system::error_code ec;
    boost::asio::ip::address_v4::from_string(cfg.bind_ip, ec);
    if (ec) {
        std::cerr << "bind_ip must be a valid IPv4 address\n";
        return 2;
    }

    Logger logger(cfg.log_file, parse_level(cfg.log_level));
    Console console;

    boost::asio::io_context io;

    std::optional<draughts::crypto::Sm2KeyPair> identity;
    try {
        if (!cfg.identity_key_file.empty()) {
            identity.emplace(draughts::crypto::Sm2KeyPair::LoadFromPemFile(cfg.identity_key_file));
        } else {
            identity.emplace();
        }
    } catch (const std::exception& e) {
        std::cerr << "failed to load identity key: " << e.what() << "\n";
        return 2;
    }

    auto pub_raw = identity->public_key_raw();
    std::vector<uint8_t> pub_vec(pub_raw.begin(), pub_raw.end());

    proto::PeerDescriptor self;
    self.peer_id = cfg.peer_id;
    self.pubkey = b64::encode(pub_vec);

    IoLayer io_layer(io, logger);
    HyparviewOverlay overlay(io_layer, cfg, self, logger);
    DraughtsApp app(io, cfg, overlay, io_layer, std::move(*identity), logger);
    app.set_notify([&console](const std::string& line) { console.println(line); });

    io_layer.set_overlay_handler([&overlay](const tlv::Bytes& bytes,
                                            const boost::asio::ip::udp::endpoint& from) {
        overlay.on_datagram(bytes, from);
    });
    io_layer.set_draughts_handler([&app](const tlv::Bytes& bytes,
                                         const boost::asio::ip::udp::endpoint& from) {
        app.on_datagram(bytes, from);
    });
    if (!io_layer.start(cfg.bind_ip, cfg.overlay_port, cfg.draughts_port)) {
        std::cerr << "failed to start io layer (bind failed)\n";
        return 2;
    }

    if (!overlay.start()) {
        std::cerr << "failed to start overlay\n";
        return 2;
    }
    if (!app.start()) {
        std::cerr << "failed to start draughts app\n";
        return 2;
    }

    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code&, int) {
        app.stop();
        overlay.stop();
        io_layer.stop();
        io.stop();
    });

    std::unique_ptr<Cli> cli;
    if (cfg.cli_enabled) {
        cli = std::make_unique<Cli>(io, overlay, app, console);
        cli->start();
    }

    io.run();
    if (cli) cli->join();

    return 0;
}
