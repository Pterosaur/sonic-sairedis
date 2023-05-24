#include <dlfcn.h>

#include <boost/filesystem.hpp>

#include <swss/logger.h>
#include <DashSai.h>

const std::string DashSai::LibPath = "/usr/lib/libsai-dash/libsai-dash.so";

DashSai::DashSai(const std::string &lib_path)
{
    SWSS_LOG_ENTER();

    m_dl_handle = dlopen(lib_path.c_str(), RTLD_NOW | RTLD_LOCAL);

    if (m_dl_handle == nullptr)
    {
        SWSS_LOG_ERROR("Failed to load library %s", lib_path.c_str());
        throw std::runtime_error(dlerror());
    }

    m_sai_api_query_fn = reinterpret_cast<sai_api_query_fn_t>(dlsym(m_dl_handle, "sai_api_query"));

    if (m_sai_api_query_fn == nullptr)
    {
        SWSS_LOG_ERROR("Failed to load sai_api_query function");
        throw std::runtime_error(dlerror());
    }
}

DashSai::~DashSai()
{
    SWSS_LOG_ENTER();

    dlclose(m_dl_handle);
}

const DashSai* DashSai::getInstance()
{
    SWSS_LOG_ENTER();

    if (boost::filesystem::exists(DashSai::LibPath) == false)
    {
        SWSS_LOG_NOTICE("Dash SAI library %s does not exist", DashSai::LibPath.c_str());
        return nullptr;
    }

    try
    {
        static DashSai instance(DashSai::LibPath);

        if (instance.isAvailable())
        {
            return &instance;
        }
    }
    catch(const std::exception& e)
    {
        SWSS_LOG_ERROR("Fail to load Dash SAI: %s", e.what());
    }

    return nullptr;
}

sai_status_t DashSai::sai_api_query(
    _In_ sai_api_t sai_api_id,
    _Out_ void** api_method_table) const
{
    return m_sai_api_query_fn(sai_api_id, api_method_table);
}

bool DashSai::isAvailable() const
{
    return m_dl_handle != nullptr 
            && m_sai_api_query_fn != nullptr;
}
