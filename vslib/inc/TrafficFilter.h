#pragma once

#include <swss/sal.h>

#include <memory>
#include <map>
#include <mutex>

namespace saivs
{

enum FilterPriority
{
    MACSEC_FILTER,
};

class TrafficFilter
{
 public:
    enum FilterStatus
    {
        CONTINUE,
        TERMINATE,
        ERROR,
    };

    virtual FilterStatus execute(
        _Inout_ void *buffer,
        _Inout_ ssize_t &length) = 0;
};

// TODO : To use RCU strategy to update filter pipes
class TrafficFilterPipes
{
 public:

    TrafficFilterPipes() = default;

    ~TrafficFilterPipes() = default;

    bool installFilter(
        _In_ int priority,
        _In_ std::shared_ptr<TrafficFilter> filter);

    bool uninstallFilter(
        _In_ std::shared_ptr<TrafficFilter> filter);

    TrafficFilter::FilterStatus execute(
        _Inout_ void *buffer,
        _Inout_ ssize_t &length);

 private:

    typedef std::map<int, std::shared_ptr<TrafficFilter> > FilterPriorityQueue;
    std::mutex m_mutex;
    FilterPriorityQueue m_filters;
};

}  // namespace saivs
