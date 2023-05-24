#include <gtest/gtest.h>

extern "C" {
#include "sai.h"
#include "saiextensions.h"
}

#include "swss/logger.h"

TEST(libsaivs, dash_sai)
{
    sai_acl_api_t *api = nullptr;

    EXPECT_EQ(SAI_STATUS_SUCCESS, sai_api_query(static_cast<sai_api_t>(static_cast<sai_api_extensions_t>(57)), (void**)&api));
}