#pragma once

#include <sai.h>
#include <saitypes.h>

#include <string>

class DashSai
{
    public:
        ~DashSai();

        sai_status_t sai_api_query(
            _In_ sai_api_t sai_api_id,
            _Out_ void** api_method_table) const;

        bool isAvailable() const;

        static const DashSai* getInstance();

    private:
        DashSai(const std::string &lib_path);

        using sai_api_query_fn_t = sai_status_t (*)(sai_api_t sai_api_id, void** api_method_table);

        void *m_dl_handle;

        sai_api_query_fn_t m_sai_api_query_fn;

        static const std::string LibPath;
};
