// Copyright (c) 2022-2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_dkgsession.h>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(llmq_dkg_tests)

BOOST_AUTO_TEST_CASE(llmq_dkgerror)
{
    using namespace llmq;
    for (auto i = 0; i< llmq::DKGError::type::_COUNT;i++) {
        BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type(i)) == 0.0);
        SetSimulatedDKGErrorRate(llmq::DKGError::type(i), 1.0);
        BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type(i)) == 1.0);
    }
    BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type::_COUNT) == 0.0);
    SetSimulatedDKGErrorRate(llmq::DKGError::type::_COUNT, 1.0);
    BOOST_ASSERT(GetSimulatedErrorRate(llmq::DKGError::type::_COUNT) == 0.0);
}



BOOST_AUTO_TEST_SUITE_END()
