#include "workload.h"

#include <iostream>

Workload::Workload(std::size_t size)
{
    reset();
    setSize(size);
}

void Workload::reset()
{
    m_nextWorkload = 1;
    m_halt = false;
    m_pause = false;
}

void Workload::setSize(std::size_t size)
{
    if (0x100000000LL % size)
    {
        std::cout << "workload size must be divisor of 0x100000000\n";
        std::abort();
    }

    m_workloadSize = size;
    m_nextWorkload = 1;
    m_workloads = 0x100000000LL/size;
}

std::size_t Workload::Workload::acquireWorkload()
{
    std::unique_lock<std::mutex> lk(m_mutex);

    if (m_pause)
    {
        m_cv.wait(lk);
    }

    if (m_nextWorkload > m_workloads || m_halt)
    {
        m_halt = true;
        return 0;
    }

    return m_nextWorkload++;
}

std::size_t Workload::currentWorkload() const
{
    return m_nextWorkload;
}

std::size_t Workload::maxWorkloads() const
{
    return m_workloads;
}

std::size_t Workload::size() const
{
    return m_workloadSize;
}

void Workload::pause()
{
    m_pause = true;
}

void Workload::resume()
{
    m_pause = false;
    m_cv.notify_all();
}

void Workload::halt()
{
    m_halt = true;
}

bool Workload::isHalted() const
{
    return m_halt;
}
