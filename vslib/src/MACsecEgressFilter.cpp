#include "MACsecEgressFilter.h"

#include <swss/logger.h>

#include <unistd.h>
#include <string.h>

using namespace saivs;

MACsecEgressFilter::MACsecEgressFilter(
    _In_ const std::string &macsec_interface_name,
    _In_ int macsecfd):
    MACsecFilter(macsec_interface_name, macsecfd)
{
    SWSS_LOG_ENTER();

    // empty intentionally
}

TrafficFilter::FilterStatus MACsecEgressFilter::forward(
    _In_ const void *buffer,
    _In_ ssize_t length)
{
    SWSS_LOG_ENTER();

    if (write(m_macsecfd, buffer, length) < 0)
    {

        if (errno != ENETDOWN && errno != EIO)
        {
            SWSS_LOG_ERROR(
                "failed to write to macsec device %s fd %d, errno(%d): %s",
                m_macsec_interface_name.c_str(),
                m_macsecfd,
                errno,
                strerror(errno));
        }

        if (errno == EBADF)
        {
            // bad file descriptor, just end thread
            SWSS_LOG_ERROR(
                "ending thread for macsec device %s fd %d",
                m_macsec_interface_name.c_str(),
                m_macsecfd);
            return TrafficFilter::ERROR;
        }

    }

    return TrafficFilter::TERMINATE;
}