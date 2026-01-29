#pragma once

#include <random>

struct Ciplc {
    double a = 1.0;
    double b = 0.1;
    double c = 3.0;
    double epsilon = 0.008;
    double x = 0.03;

    bool step_and_decide(std::mt19937& rng);
};

