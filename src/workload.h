#pragma once

#include <atomic>
#include <mutex>
#include <condition_variable>

class Workload
{
public:
    Workload(std::size_t size);

    void reset();

    void setSize(std::size_t size);

    std::size_t acquireWorkload();
    std::size_t currentWorkload() const;
    std::size_t maxWorkloads() const;
    std::size_t size() const;

    void pause();
    void resume();
    void halt();
    bool isHalted() const;

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic_bool m_pause, m_halt;
    std::size_t m_nextWorkload;
    std::size_t m_workloadSize;
    std::size_t m_workloads;
    unsigned int m_currentPercentage = 0;
};
