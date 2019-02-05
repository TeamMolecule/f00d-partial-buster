#pragma once

#include "solver.h"

class AES;
class Workload;

class MultishotSolver : public Solver
{
public:
    enum Type
    {
        Encrypt,
        Decrypt
    };

    MultishotSolver(const Partials& partials, Type keyType, Type partialType)
        : m_partials(partials)
        , m_concurrency(std::thread::hardware_concurrency())
        , m_workloadSize(0x10000)
        , m_keyType(keyType)
        , m_partialType(partialType)
    {

    }

private:
    std::future<std::optional<Key>> solveProcess() override;

    std::vector<Key> partialBruteforce(AES *aes, std::vector<uint8_t> &workBuffer, Workload *workloadServer, Key base, int offset, const std::vector<std::uint8_t>& expected);
    std::optional<Key> keyBruteforce(AES *aes, Workload *workloadServer, Key base, int offset, const std::vector<std::uint8_t>& expected);
    std::optional<Key> partialBruteforceChain(Workload *workload, Key base, int offset, std::vector<std::uint8_t> expected, std::function<std::optional<Key>(Key key)> next);

    std::optional<Key> solveStage1(Key base);
    std::optional<Key> solveStage2(Key base);
    std::optional<Key> solveStage3(Key base);
    std::optional<Key> solveStage4(Key base);

private:
    Partials m_partials;
    int m_concurrency = 8;
    std::size_t m_workloadSize;
    std::atomic_bool m_keyFound = false;
    Type m_keyType, m_partialType;
};
