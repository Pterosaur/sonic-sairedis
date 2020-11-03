#pragma once

#include "MACsecFilter.h"

namespace saivs
{

    class MACsecEgressFilter
        : public MACsecFilter
    {
    public:
        MACsecEgressFilter(
            _In_ const std::string &macsec_interface_name,
            _In_ int macsecfd);

    protected:
        FilterStatus forward(
            _In_ const void *buffer,
            _In_ ssize_t length) override;
    };

}  // namespace saivs
