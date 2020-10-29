#pragma once

#include "TrafficFilter.h"
#include "HostInterfaceInfo.h"

#include <swss/selectableevent.h>

#include <string>
#include <thread>
#include <cinttypes>

namespace saivs
{

    using macsec_sci_t = std::string;
    using macsec_an_t = std::uint16_t;
    using macsec_pn_t = std::uint64_t;

    struct MACsecAttr
    {
        std::string m_veth_name;
        std::string m_macsec_name;
        std::string m_auth_key;
        std::string m_sak;
        std::string m_sci;
        macsec_an_t m_an;
        macsec_pn_t m_pn;
        bool m_send_sci;
        bool m_encryption_enable;
        sai_int32_t m_direction;
        std::shared_ptr<HostInterfaceInfo> m_info;

        // Explicitely declare constructor and destructor as non-inline functions
        // to avoid 'call is unlikely and code size would grow [-Werror=inline]'
        // in "-O3" optimization
        MACsecAttr();

        ~MACsecAttr();
    };

    class MACsecForwarder
    {
    public:
        MACsecForwarder(
            _In_ const std::string &macsec_interface_name,
            _In_ int tapfd);

        virtual ~MACsecForwarder();

        int get_macsecfd() const;

        void forward();

    private:
        int m_tapfd;
        int m_vethfd;
        int m_macsecfd;
        const std::string m_macsec_interface_name;
        bool m_run_thread;
        swss::SelectableEvent m_exit_event;
        std::shared_ptr<std::thread> m_forward_thread;
    };

    class MACsecFilter
        : public TrafficFilter
    {
    public:
        MACsecFilter(
            _In_ const std::string &macsec_interface_name,
            _In_ int macsecfd);

        virtual ~MACsecFilter() = default;

        FilterStatus execute(
            _Inout_ void *buffer,
            _Inout_ ssize_t &length) override;

    protected:
        int m_macsecfd;
        const std::string m_macsec_interface_name;
        virtual FilterStatus forward(
            _In_ const void *buffer,
            _In_ ssize_t length) = 0;
    };

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

    class MACsecIngressFilter
        : public MACsecFilter
    {
    public:
        MACsecIngressFilter(
            _In_ const std::string &macsec_interface_name,
            _In_ int macsecfd);

    protected:
        FilterStatus forward(
            _In_ const void *buffer,
            _In_ ssize_t length) override;
    };

    class MACsecManager
    {
    public:
        MACsecManager() = default;
        ~MACsecManager() = default;

        bool create_macsec_port(
            _In_ const MACsecAttr &attr);

        bool create_macsec_egress_sa(
            _In_ const MACsecAttr &attr);

        bool create_macsec_ingress_sc(
            _In_ const MACsecAttr &attr);

        bool create_macsec_ingress_sa(
            _In_ const MACsecAttr &attr);

        bool enable_macsec(
            _In_ const MACsecAttr &attr);

        bool delete_macsec_port(
            _In_ const MACsecAttr &attr);

        bool delete_macsec_egress_sa(
            _In_ const MACsecAttr &attr);

        bool delete_macsec_ingress_sc(
            _In_ const MACsecAttr &attr);

        bool delete_macsec_ingress_sa(
            _In_ const MACsecAttr &attr);

        bool get_macsec_sa_pn(
            _In_ const MACsecAttr &attr,
            _Out_ sai_uint64_t &pn);

    private:

        bool add_macsec_manager(
            _In_ const std::string &macsec_interface,
            _In_ std::shared_ptr<HostInterfaceInfo> info);

        bool delete_macsec_traffic_manager(
            _In_ const std::string &macsec_interface);

        bool get_macsec_device_info(
            _In_ const std::string &macsec_device,
            _Out_ std::string &info);

        bool is_macsec_device_existing(
            _In_ const std::string &macsec_device);

        struct MACsecTrafficManager
        {
            std::shared_ptr<HostInterfaceInfo> m_info;
            std::shared_ptr<MACsecFilter> m_ingress_filter;
            std::shared_ptr<MACsecFilter> m_egress_filter;
            std::shared_ptr<MACsecForwarder> m_forwarder;

            MACsecTrafficManager() = default;

            ~MACsecTrafficManager() = default;
        };

        std::map<std::string, MACsecTrafficManager> m_macsec_traffic_managers;

        std::string shellquote(
            _In_ const std::string &str);

        bool exec(
            _In_ const std::string &command,
            _Out_ std::string &output);

        bool exec(
            _In_ const std::string &command);

    };

}  // namespace saivs
