#include "io_layer.hpp"

#include <memory>
#include <utility>

using boost::asio::ip::make_address_v4;

IoLayer::IoLayer(boost::asio::io_context& io, Logger& logger)
    : io_(io),
      logger_(logger),
      overlay_sock_(io_),
      draughts_sock_(io_) {}

bool IoLayer::start(const std::string& bind_ip, uint16_t overlay_port, uint16_t draughts_port) {
    boost::system::error_code ec;

    overlay_sock_.open(udp::v4(), ec);
    if (ec) {
        logger_.error("failed to open overlay socket: " + ec.message());
        return false;
    }
    overlay_sock_.bind(udp::endpoint(make_address_v4(bind_ip), overlay_port), ec);
    if (ec) {
        logger_.error("failed to bind overlay socket: " + ec.message() +
                      " (addr=" + bind_ip + ":" + std::to_string(overlay_port) + ")");
        return false;
    }

    draughts_sock_.open(udp::v4(), ec);
    if (ec) {
        logger_.error("failed to open draughts socket: " + ec.message());
        return false;
    }
    draughts_sock_.bind(udp::endpoint(make_address_v4(bind_ip), draughts_port), ec);
    if (ec) {
        logger_.error("failed to bind draughts socket: " + ec.message() +
                      " (addr=" + bind_ip + ":" + std::to_string(draughts_port) + ")");
        return false;
    }

    do_receive_overlay();
    do_receive_draughts();
    return true;
}

void IoLayer::stop() {
    boost::system::error_code ec;
    overlay_sock_.close(ec);
    draughts_sock_.close(ec);
}

void IoLayer::set_overlay_handler(ReceiveHandler handler) {
    on_overlay_ = std::move(handler);
}

void IoLayer::set_draughts_handler(ReceiveHandler handler) {
    on_draughts_ = std::move(handler);
}

void IoLayer::send_overlay(const tlv::Bytes& bytes, const udp::endpoint& to) {
    auto buf = std::make_shared<tlv::Bytes>(bytes);
    overlay_sock_.async_send_to(boost::asio::buffer(*buf), to, [buf](auto, auto) {});
}

void IoLayer::send_draughts(const tlv::Bytes& bytes, const udp::endpoint& to) {
    auto buf = std::make_shared<tlv::Bytes>(bytes);
    draughts_sock_.async_send_to(boost::asio::buffer(*buf), to, [buf](auto, auto) {});
}

boost::asio::io_context& IoLayer::context() {
    return io_;
}

IoLayer::udp::endpoint IoLayer::overlay_local_endpoint() const {
    boost::system::error_code ec;
    auto ep = overlay_sock_.local_endpoint(ec);
    return ec ? udp::endpoint{} : ep;
}

IoLayer::udp::endpoint IoLayer::draughts_local_endpoint() const {
    boost::system::error_code ec;
    auto ep = draughts_sock_.local_endpoint(ec);
    return ec ? udp::endpoint{} : ep;
}

void IoLayer::do_receive_overlay() {
    overlay_sock_.async_receive_from(boost::asio::buffer(overlay_rxbuf_), overlay_remote_,
                                     [this](boost::system::error_code ec, std::size_t n) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted) {
                logger_.warn(std::string("overlay recv error: ") + ec.message());
            }
            return;
        }
        if (on_overlay_) {
            tlv::Bytes bytes(overlay_rxbuf_.begin(), overlay_rxbuf_.begin() + n);
            on_overlay_(bytes, overlay_remote_);
        }
        do_receive_overlay();
    });
}

void IoLayer::do_receive_draughts() {
    draughts_sock_.async_receive_from(boost::asio::buffer(draughts_rxbuf_), draughts_remote_,
                                      [this](boost::system::error_code ec, std::size_t n) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted) {
                logger_.warn(std::string("draughts recv error: ") + ec.message());
            }
            return;
        }
        if (on_draughts_) {
            tlv::Bytes bytes(draughts_rxbuf_.begin(), draughts_rxbuf_.begin() + n);
            on_draughts_(bytes, draughts_remote_);
        }
        do_receive_draughts();
    });
}
