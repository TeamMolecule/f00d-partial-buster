#include "multishotsolver.h"

#include "aes.h"
#include "hex.h"
#include "workload.h"

#include <string.h>
#include <cstring>
#include <vector>

std::vector<Key> MultishotSolver::partialBruteforce(AES *aes, std::vector<uint8_t> &workBuffer, Workload *workloadServer, Key base, int offset, const std::vector<std::uint8_t>& expected)
{
    std::vector<Key> solutions;

    auto workload = workloadServer->acquireWorkload();

    if (!workload)
        return {};

    // TODO: check casts
    uint32_t start = static_cast<uint32_t>((workload-1)*workloadServer->size());

    for (auto i = 0u; i < workloadServer->size(); ++i)
    {
        uint32_t keyPart = static_cast<uint32_t>(start+i);
        base.data.dwords[offset/4] = keyPart;
        std::memcpy(workBuffer.data()+i*0x10, base.data.bytes, 0x10);
    }

    if (m_partialType == Encrypt)
    {
        aes->encrypt(workBuffer);
    }
    else
    {
        aes->decrypt(workBuffer);
    }

    for (auto i = 0u; i < workloadServer->size(); ++i)
    {
        if (std::memcmp(expected.data(), workBuffer.data()+i*0x10, expected.size()) == 0)
        {
            uint32_t keyPart = start+i;
            base.data.dwords[offset/4] = keyPart;
            solutions.push_back(base);
        }
    }

    return solutions;
}

std::optional<Key> MultishotSolver::keyBruteforce(AES *aes, Workload *workloadServer, Key base, int offset, const std::vector<std::uint8_t>& expected)
{
    uint8_t enc[0x10];
    uint8_t zeroes[0x10];

    memset(zeroes, 0, sizeof(zeroes));

    auto workload = workloadServer->acquireWorkload();

    if (!workload)
        return {};

    // TODO: check casts
    auto start = static_cast<uint32_t>((workload-1)*workloadServer->size());

    for (auto i = 0u; i < workloadServer->size(); ++i)
    {
        uint32_t keyPart = start+i;
        base.data.dwords[offset/4] = keyPart;

        aes->setKey(&base);

        if (m_keyType == Encrypt)
        {
            aes->encrypt(enc, zeroes, sizeof(enc));
        }
        else
        {
            aes->decrypt(enc, zeroes, sizeof(enc));
        }

        if (std::memcmp(expected.data(), enc, expected.size()) == 0)
        {
            return base;
        }
    }

    return {};
}

std::optional<Key> MultishotSolver::partialBruteforceChain(Workload *workload, Key base, int offset, std::vector<std::uint8_t> expected, std::function<std::optional<Key>(Key key)> next)
{
    std::vector<std::future<std::optional<Key>>> solutions;
    Key zeros;
    AES aes;
    aes.setKey(&zeros);

    std::vector<uint8_t> workBuffer(workload->size()*0x10);

    while (!workload->isHalted() && !m_keyFound)
    {
        // we may have many results or none
        auto results = partialBruteforce(&aes, workBuffer, workload, base, offset, expected);

        for (auto key : results)
        {
            solutions.push_back(std::async(std::launch::async, [this, next, key]()
            {
                return next(key);
            }));
        }
    }

    for (auto& solution : solutions)
    {
        auto key = solution.get();

        if (key)
        {
            workload->halt();
            return key;
        }
    }

    return {};
}

std::optional<Key> MultishotSolver::solveStage1(Key base)
{
    // stage one we take the four partial and AES decrypt with key 00's until we have a match.
    // only the tail 32 bits have an unknown state (96 bits prior are 0)
    Workload workload(m_workloadSize);
    std::vector<std::future<std::optional<Key>>> solutions;

    for (int i = 0; i < m_concurrency; ++i)
    {
        solutions.push_back(std::async(std::launch::async, [this, &workload, base]()
        {
            return partialBruteforceChain(&workload, base, 0xC, m_partials.four, [this, &workload](auto key)
            {
                workload.pause();
                auto result = this->solveStage2(key);
                workload.resume();
                return result;
            });
        }));
    }

    for (auto& solution : solutions)
    {
        auto key = solution.get();

        if (key)
            return key;
    }

    return {};
}

std::optional<Key> MultishotSolver::solveStage2(Key base)
{
    // stage two we take the eight partial and AES decrypt with key 00's until we have a match.
    // only the tail 64 bits have non-zero state (64 bits prior are 0) and the last 32 bits belong are
    // derived from stage 1.
    Workload workload(m_workloadSize);
    std::vector<std::future<std::optional<Key>>> solutions;

    for (int i = 0; i < m_concurrency; ++i)
    {
        solutions.push_back(std::async(std::launch::async, [this, &workload, base]()
        {
            return partialBruteforceChain(&workload, base, 0x8, m_partials.eight, [this, &workload](auto key)
            {
                workload.pause();
                auto result = this->solveStage3(key);
                workload.resume();
                return result;
            });
        }));
    }

    for (auto& solution : solutions)
    {
        auto key = solution.get();

        if (key)
            return key;
    }

    return {};
}

std::optional<Key> MultishotSolver::solveStage3(Key base)
{
    Workload workload(m_workloadSize);
    std::vector<std::future<std::optional<Key>>> solutions;

    for (int i = 0; i < m_concurrency; ++i)
    {
        solutions.push_back(std::async(std::launch::async, [this, &workload, base]()
        {
            return partialBruteforceChain(&workload, base, 0x4, m_partials.twelve, [this, &workload](auto key)
            {
                workload.pause();
                auto result = this->solveStage4(key);
                workload.resume();
                return result;
            });
        }));
    }

    for (auto& solution : solutions)
    {
        auto key = solution.get();

        if (key)
            return key;
    }

    return {};
}

std::optional<Key> MultishotSolver::solveStage4(Key base)
{
    Workload workload(m_workloadSize);
    std::vector<std::future<std::optional<Key>>> solutions;

    for (int i = 0; i < m_concurrency; ++i)
    {
        solutions.push_back(std::async(std::launch::async, [this, &workload, base]() -> std::optional<Key>
        {
            AES aes;

            while (!workload.isHalted() && !m_keyFound)
            {
                // we should only expect one result, if any
                auto key = keyBruteforce(&aes, &workload, base, 0, m_partials.full);

                if (key)
                {
                    workload.halt();
                    m_keyFound = true;
                    return key;
                }
            }

            return {};
        }));
    }

    for (auto& solution : solutions)
    {
        auto key = solution.get();

        if (key)
            return key;
    }

    return {};
}

std::future<std::optional<Key>> MultishotSolver::solveProcess()
{
    Key key;
    m_keyFound = false;
    return std::async(std::launch::async, [this, key]() { return this->solveStage1(key); });
}
