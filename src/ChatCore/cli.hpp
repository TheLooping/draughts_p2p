#pragma once

#include <boost/asio.hpp>

#include <atomic>
#include <string>
#include <thread>

#include "console.hpp"
#include "draughts_app.hpp"
#include "node.hpp"

class Cli {
public:
    Cli(boost::asio::io_context& io, DraughtsNode& node, DraughtsApp& app, Console& console);

    void start();
    void join();

private:
    void run();

    boost::asio::io_context& io_;
    DraughtsNode& node_;
    DraughtsApp& app_;
    Console& console_;

    std::atomic<bool> stop_{false};
    std::thread th_;
};

