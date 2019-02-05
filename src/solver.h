#pragma once

#include "key.h"

#include <future>
#include <optional>
#include <vector>

#include <cstring>

typedef struct
{
    std::vector<std::uint8_t> full;
    std::vector<std::uint8_t> four;
    std::vector<std::uint8_t> eight;
    std::vector<std::uint8_t> twelve;
} Partials;

class Solver
{
public:
    std::future<std::optional<Key>> solve()
    {
        return solveProcess();
    }

private:
    virtual std::future<std::optional<Key>> solveProcess() = 0;

private:
    Partials m_partials;
    int m_concurrency = 8;
    std::size_t m_workloadSize;
    std::atomic_bool m_keyFound;
};
