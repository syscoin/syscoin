#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpcserver.h"
#include <boost/test/unit_test.hpp>
BOOST_FIXTURE_TEST_SUITE (syscoin_escrow_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_escrow_release)
{
	printf("Running generate_escrow_release...\n");
	UniValue r;
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "buyeralias", "changeddata1");
	AliasNew("node2", "selleralias", "changeddata2");
	AliasNew("node3", "arbiteralias", "changeddata3");
	string qty = "3";
	string message = "paymentmessage";
	string offerguid = OfferNew("node2", "selleralias", "category", "title", "100", "0.05", "description", "USD");
	string guid = EscrowNew("node1", "buyeralias", offerguid, qty, message, "arbiteralias", "selleralias");
	EscrowRelease("node1", guid);	
	EscrowClaimRelease("node2", guid);
}
BOOST_AUTO_TEST_CASE (generate_escrow_big)
{
	printf("Running generate_escrow_big...\n");
	UniValue r;
	// 255 bytes long
	string goodname1 = "SgsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	string goodname2 = "TgsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	string goodname3 = "UgsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 1023 bytes long
	string gooddata = "agdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	// 1024 bytes long
	string baddata = "azsdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
				
	AliasNew("node1", goodname1, "changeddata1");
	AliasNew("node2", goodname2, "changeddata2");
	AliasNew("node3", goodname3, "changeddata3");
	string qty = "3";

	string offerguid = OfferNew("node2", goodname2, "category", "title", "100", "0.05", "description", "USD");
	// payment message too long
	BOOST_CHECK_THROW(r = CallRPC("node1", "escrownew " + goodname1 + " " + offerguid + " " + qty + " " + baddata + " " + goodname3), runtime_error);
	string guid = EscrowNew("node1", goodname1, offerguid, qty, gooddata, goodname3, goodname2);
	EscrowRelease("node1", guid);	
	EscrowClaimRelease("node2", guid);
}
BOOST_AUTO_TEST_CASE (generate_escrowrefund_seller)
{
	AliasNew("node1", "buyeraliasrefund", "changeddata1");
	AliasNew("node2", "selleraliasrefund", "changeddata2");
	AliasNew("node3", "arbiteraliasrefund", "changeddata3");
	printf("Running generate_escrowrefund_seller...\n");
	string qty = "4";
	string message = "paymentmessage";
	string offerguid = OfferNew("node2", "selleraliasrefund", "category", "title", "100", "1.22", "description", "CAD");
	string guid = EscrowNew("node1", "buyeraliasrefund", offerguid, qty, message, "arbiteraliasrefund", "selleraliasrefund");
	EscrowRefund("node2", guid);
	EscrowRefund("node1", guid);
}
BOOST_AUTO_TEST_CASE (generate_escrowrefund_arbiter)
{
	printf("Running generate_escrowrefund_arbiter...\n");
	string qty = "5";
	string offerguid = OfferNew("node2", "selleraliasrefund", "category", "title", "100", "0.25", "description", "EUR");
	string message = "paymentmessage";
	string guid = EscrowNew("node1", "buyeraliasrefund", offerguid, qty, message, "arbiteraliasrefund", "selleraliasrefund");
	EscrowRefund("node3", guid);
	EscrowRefund("node1", guid);
}
BOOST_AUTO_TEST_CASE (generate_escrowrefund_invalid)
{
	printf("Running generate_escrowrefund_invalid...\n");
	AliasNew("node1", "buyeraliasrefund2", "changeddata1");
	AliasNew("node2", "selleraliasrefund2", "changeddata2");
	AliasNew("node3", "arbiteraliasrefund2", "changeddata3");
	string qty = "2";
	string offerguid = OfferNew("node2", "selleraliasrefund2", "category", "title", "100", "1.45", "description", "EUR");
	string guid = EscrowNew("node1", "buyeraliasrefund2", offerguid, qty, "message", "arbiteraliasrefund2", "selleraliasrefund2");
	// try to claim refund even if not refunded
	BOOST_CHECK_THROW(CallRPC("node2", "escrowclaimrefund " + guid), runtime_error);
	// buyer cant refund to himself
	BOOST_CHECK_THROW(CallRPC("node1", "escrowrefund " + guid), runtime_error);
	EscrowRefund("node2", guid);
	// try to release already refunded escrow
	BOOST_CHECK_THROW(CallRPC("node1", "escrowrelease " + guid), runtime_error);
	// cant refund already refunded escrow
	BOOST_CHECK_THROW(CallRPC("node2", "escrowrefund " + guid), runtime_error);
	// noone other than buyer can claim release
	BOOST_CHECK_THROW(CallRPC("node3", "escrowclaimrefund " + guid), runtime_error);
	BOOST_CHECK_THROW(CallRPC("node2", "escrowclaimrefund " + guid), runtime_error);
	EscrowRefund("node1", guid);
	// cant inititate another refund after claimed already
	BOOST_CHECK_THROW(CallRPC("node1", "escrowrefund " + guid), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_escrowrelease_invalid)
{
	printf("Running generate_escrowrelease_invalid...\n");
	string qty = "4";
	AliasNew("node1", "buyeraliasrefund3", "changeddata1");
	AliasNew("node2", "selleraliasrefund3", "changeddata2");
	AliasNew("node3", "arbiteraliasrefund3", "changeddata3");
	string offerguid = OfferNew("node2", "selleraliasrefund3", "category", "title", "100", "1.45", "description", "SYS");
	string guid = EscrowNew("node1", "buyeraliasrefund3", offerguid, qty, "message", "arbiteraliasrefund3", "selleraliasrefund3");
	// try to claim release even if not released
	BOOST_CHECK_THROW(CallRPC("node2", "escrowclaimrelease " + guid), runtime_error);
	// seller cant release buyers funds
	BOOST_CHECK_THROW(CallRPC("node2", "escrowrelease " + guid), runtime_error);
	EscrowRelease("node1", guid);
	// try to refund already released escrow
	BOOST_CHECK_THROW(CallRPC("node2", "escrowrefund " + guid), runtime_error);
	// cant release already released escrow
	BOOST_CHECK_THROW(CallRPC("node1", "escrowrelease " + guid), runtime_error);
	// noone other than seller can claim release
	BOOST_CHECK_THROW(CallRPC("node3", "escrowclaimrelease " + guid), runtime_error);
	BOOST_CHECK_THROW(CallRPC("node1", "escrowclaimrelease " + guid), runtime_error);
	EscrowClaimRelease("node2", guid);
	// cant inititate another release after claimed already
	BOOST_CHECK_THROW(CallRPC("node1", "escrowrelease " + guid), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_escrowrelease_arbiter)
{
	printf("Running generate_escrowrelease_arbiter...\n");
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "buyeralias1", "changeddata1");
	AliasNew("node2", "selleralias111", "changeddata2");
	AliasNew("node3", "arbiteralias1", "changeddata3");
	UniValue r;
	string qty = "1";
	string offerguid = OfferNew("node2", "selleralias111", "category", "title", "100", "0.05", "description", "GBP");
	string guid = EscrowNew("node1", "buyeralias1", offerguid, qty, "message", "arbiteralias1", "selleralias111");
	EscrowRelease("node3", guid);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "escrowinfo " + guid));
	CAmount escrowfee = AmountFromValue(find_value(r.get_obj(), "sysfee"));
	// get arbiter balance (ensure he gets escrow fees, since he stepped in and released)
	BOOST_CHECK_NO_THROW(r = CallRPC("node3", "getinfo"));
	CAmount balanceBeforeArbiter = AmountFromValue(find_value(r.get_obj(), "balance"));
	EscrowClaimRelease("node2", guid);
	// get arbiter balance after release
	BOOST_CHECK_NO_THROW(r = CallRPC("node3", "getinfo"));
	// 10 mined block subsidy + escrow fee
	balanceBeforeArbiter += escrowfee;
	CAmount balanceAfterArbiter = AmountFromValue(find_value(r.get_obj(), "balance"));
	BOOST_CHECK(abs(balanceBeforeArbiter - balanceAfterArbiter) <= COIN);
	


}
BOOST_AUTO_TEST_CASE (generate_escrow_linked_release)
{
	printf("Running generate_escrow_linked_release...\n");
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "buyeralias2", "changeddata1");
	AliasNew("node2", "selleralias22", "changeddata2");
	AliasNew("node3", "arbiteralias2", "changeddata3");
	string qty = "3";
	string message = "paymentmessage";
	string offerguid = OfferNew("node2", "selleralias22", "category", "title", "100", "0.04", "description", "EUR");
	string commission = "10";
	string description = "newdescription";
	// offer should be set to exclusive mode by default so linking isn't allowed
	BOOST_CHECK_THROW(CallRPC("node3", "offerlink arbiteralias2 " + offerguid + " " + commission + " " + description), runtime_error);
	offerguid = OfferNew("node2", "selleralias22", "category", "title", "100", "0.04", "description", "EUR", "nocert", false);
	string offerlinkguid = OfferLink("node3", "arbiteralias2", offerguid, commission, description);
	string guid = EscrowNew("node1", "buyeralias2", offerlinkguid, qty, message, "arbiteralias2", "selleralias22");
	EscrowRelease("node1", guid);
	// reseller cant claim escrow, seller must claim it
	BOOST_CHECK_THROW(CallRPC("node3", "escrowclaimrelease " + guid), runtime_error);
	AliasUpdate("node1", "buyeralias2", "changeddata1", "priv");
	AliasUpdate("node2", "selleralias22", "changeddata1", "priv");
	AliasUpdate("node3", "arbiteralias2", "changeddata1", "priv");
	OfferUpdate("node2", "selleralias22", offerguid, "category", "titlenew", "100", "0.04", "descriptionnew", false, "nocert", false, "location");
	EscrowClaimReleaseLink("node2", guid, "node3");
}
BOOST_AUTO_TEST_CASE (generate_escrow_linked_release_with_peg_update)
{
	printf("Running generate_escrow_linked_release_with_peg_update...\n");
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "buyeralias33", "changeddata1");
	AliasNew("node2", "selleralias33", "changeddata2");
	AliasNew("node3", "arbiteralias333", "changeddata3");
	string qty = "3";
	string message = "paymentmessage";
	string offerguid = OfferNew("node2", "selleralias33", "category", "title", "100", "0.05", "description", "EUR", "nocert", false);
	string commission = "3";
	string description = "newdescription";
	string offerlinkguid = OfferLink("node3", "arbiteralias333", offerguid, commission, description);
	string guid = EscrowNew("node1", "buyeralias33", offerlinkguid, qty, message, "arbiteralias333", "selleralias33");
	EscrowRelease("node1", guid);
	// update the EUR peg twice before claiming escrow
	string data = "{\\\"rates\\\":[{\\\"currency\\\":\\\"USD\\\",\\\"rate\\\":2690.1,\\\"precision\\\":2},{\\\"currency\\\":\\\"EUR\\\",\\\"rate\\\":269.2,\\\"precision\\\":2},{\\\"currency\\\":\\\"GBP\\\",\\\"rate\\\":2697.3,\\\"precision\\\":2},{\\\"currency\\\":\\\"CAD\\\",\\\"rate\\\":2698.0,\\\"precision\\\":2},{\\\"currency\\\":\\\"BTC\\\",\\\"rate\\\":100000.0,\\\"precision\\\":8},{\\\"currency\\\":\\\"SYS\\\",\\\"rate\\\":1.0,\\\"precision\\\":2}]}";
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate SYS_RATES " + data));
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	data = "{\\\"rates\\\":[{\\\"currency\\\":\\\"USD\\\",\\\"rate\\\":2690.1,\\\"precision\\\":2},{\\\"currency\\\":\\\"EUR\\\",\\\"rate\\\":218.2,\\\"precision\\\":2},{\\\"currency\\\":\\\"GBP\\\",\\\"rate\\\":2697.3,\\\"precision\\\":2},{\\\"currency\\\":\\\"CAD\\\",\\\"rate\\\":2698.0,\\\"precision\\\":2},{\\\"currency\\\":\\\"BTC\\\",\\\"rate\\\":100000.0,\\\"precision\\\":8},{\\\"currency\\\":\\\"SYS\\\",\\\"rate\\\":1.0,\\\"precision\\\":2}]}";
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate SYS_RATES " + data));
	// ensure dependent services don't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate buyeralias33 data"));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate selleralias33 data"));
	BOOST_CHECK_NO_THROW(CallRPC("node3", "aliasupdate arbiteralias333 data"));

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	MilliSleep(2500);
	EscrowClaimReleaseLink("node2", guid, "node3");
	// restore EUR peg
	data = "{\\\"rates\\\":[{\\\"currency\\\":\\\"USD\\\",\\\"rate\\\":2690.1,\\\"precision\\\":2},{\\\"currency\\\":\\\"EUR\\\",\\\"rate\\\":2695.2,\\\"precision\\\":2},{\\\"currency\\\":\\\"GBP\\\",\\\"rate\\\":2697.3,\\\"precision\\\":2},{\\\"currency\\\":\\\"CAD\\\",\\\"rate\\\":2698.0,\\\"precision\\\":2},{\\\"currency\\\":\\\"BTC\\\",\\\"rate\\\":100000.0,\\\"precision\\\":8},{\\\"currency\\\":\\\"SYS\\\",\\\"rate\\\":1.0,\\\"precision\\\":2}]}";
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate SYS_RATES " + data));
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
}
BOOST_AUTO_TEST_CASE (generate_escrowpruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes
	#ifdef ENABLE_DEBUGRPC
		printf("Running generate_escrowpruning...\n");
		AliasNew("node1", "selleraliasprune", "changeddata2");
		AliasNew("node2", "buyeraliasprune", "changeddata2");
		string offerguid = OfferNew("node1", "SYS_RATES", "category", "title", "100", "0.05", "description", "USD");
		// stop node3
		StopNode("node3");
		// create a new service
		BOOST_CHECK_NO_THROW(r = CallRPC("node2", "escrownew buyeraliasprune " + offerguid + " 1 message selleraliasprune"));
		const UniValue &arr1 = r.get_array();
		string guid1 = arr1[1].get_str();
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 3"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate SYS_RATES selleraliasprune " + offerguid + " category title 1 0.05 description"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
		// make sure our escrow alias doesn't expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 20"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		// stop and start node1
		StopNode("node1");
		StartNode("node1");
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		MilliSleep(2500);
		// ensure you can still update before expiry
		BOOST_CHECK_NO_THROW(CallRPC("node2", "escrowrelease " + guid1));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
		// generate 89 more blocks (10 get mined from update)
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate SYS_RATES selleraliasprune " + offerguid + " category title 2 0.05 description"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		// give some time to propogate the new blocks across other 2 nodes
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 75"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate SYS_RATES selleraliasprune " + offerguid + " category title 3 0.05 description"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		// ensure service is still active since its supposed to expire at 100 blocks of non updated services
		// this should claim the release because buyer calls it
		BOOST_CHECK_NO_THROW(CallRPC("node1", "escrowrelease " + guid1));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		MilliSleep(2500);
		// leave some feedback
		BOOST_CHECK_NO_THROW(CallRPC("node1",  "escrowfeedback " + guid1 + " 1 2 3 4"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 60"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate SYS_RATES selleraliasprune " + offerguid + " category title 4 0.05 description"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 60"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate SYS_RATES selleraliasprune " + offerguid + " category title 5 0.05 description"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 2"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate selleraliasprune newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasupdate buyeraliasprune newdata privdata"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 2"));
		MilliSleep(2500);
		// now it should be expired, try to leave feedback it shouldn't let you
		BOOST_CHECK_THROW(CallRPC("node2",  "escrowfeedback " + guid1 + " 1 2 3 4"), runtime_error);
		// and it should say its expired
		BOOST_CHECK_NO_THROW(r = CallRPC("node2", "escrowinfo " + guid1));


		StartNode("node3");
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
		MilliSleep(2500);
		// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
		BOOST_CHECK_THROW(CallRPC("node3", "escrowinfo " + guid1), runtime_error);
	#endif
}

BOOST_AUTO_TEST_SUITE_END ()