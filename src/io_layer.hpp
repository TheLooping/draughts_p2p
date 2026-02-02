#pragma once

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "logger.hpp"
#include "tlv.hpp"

class IoLayer {
public:
    using udp = boost::asio::ip::udp;
    using ReceiveHandler = std::function<void(const tlv::Bytes&, const udp::endpoint&)>;

    IoLayer(boost::asio::io_context& io, Logger& logger);

    bool start(const std::string& bind_ip, uint16_t overlay_port, uint16_t draughts_port);
    void stop();

    void set_overlay_handler(ReceiveHandler handler);
    void set_draughts_handler(ReceiveHandler handler);

    void send_overlay(const tlv::Bytes& bytes, const udp::endpoint& to);
    void send_draughts(const tlv::Bytes& bytes, const udp::endpoint& to);

    boost::asio::io_context& context();

    udp::endpoint overlay_local_endpoint() const;
    udp::endpoint draughts_local_endpoint() const;

private:
    void do_receive_overlay();
    void do_receive_draughts();

    boost::asio::io_context& io_;
    Logger& logger_;

    udp::socket overlay_sock_;
    udp::socket draughts_sock_;
    udp::endpoint overlay_remote_;
    udp::endpoint draughts_remote_;
    std::array<uint8_t, 4096> overlay_rxbuf_{};
    std::array<uint8_t, 4096> draughts_rxbuf_{};

    ReceiveHandler on_overlay_;
    ReceiveHandler on_draughts_;
};
