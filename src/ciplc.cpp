#include "ciplc.hpp"

#include <cmath>

bool Ciplc::step_and_decide(std::mt19937& rng) {
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    double r = dist(rng);

    if (x == 0.0) {
        x = 0.0;
    } else {
        double f = std::cos(1.0 / x);
        x = a * x * f * (1.0 + b * r);
    }

    double absx = std::fabs(x);
    double pf = 0.0;
    if (absx > epsilon) {
        double t = std::fabs(c * x);
        double sigmoid = 1.0 / (1.0 + std::exp(-t));
        pf = 2.0 * sigmoid - 1.0;
    }

    std::uniform_real_distribution<double> dist01(0.0, 1.0);
    double u = dist01(rng);
    return u < pf;
}

