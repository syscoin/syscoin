#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpcserver.h"
#include "alias.h"
#include <boost/test/unit_test.hpp>
BOOST_GLOBAL_FIXTURE( SyscoinTestingSetup );

BOOST_FIXTURE_TEST_SUITE (syscoin_alias_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_sysrates_alias)
{
	printf("Running generate_sysrates_alias...\n");
	CreateSysRatesIfNotExist();
	CreateSysBanIfNotExist();
	CreateSysCategoryIfNotExist();
}
BOOST_AUTO_TEST_CASE (generate_big_aliasdata)
{
	printf("Running generate_big_aliasdata...\n");
	GenerateBlocks(5);
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";
	// 1024 bytes long
	string baddata =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	AliasNew("node1", "jag", gooddata);
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew jag1 " + baddata), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_big_aliasname)
{
	printf("Running generate_big_aliasname...\n");
	GenerateBlocks(5);
	// 63 bytes long
	string goodname = "sfsdfdfsdsfsfsdfdfsdsfdsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdsfsdfd";
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	// 64 bytes long
	string badname =  "sfsdfdfsdsfsfsdfdfsdsfdsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdsfsdfda";
	AliasNew("node1", goodname, "a");
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew " + badname + " 3d"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_aliasupdate)
{
	printf("Running generate_aliasupdate...\n");
	GenerateBlocks(1);
	AliasNew("node1", "jagupdate", "data");
	// update an alias that isn't yours
	BOOST_CHECK_THROW(CallRPC("node2", "aliasupdate jagupdate test"), runtime_error);
	AliasUpdate("node1", "jagupdate", "changeddata", "privdata");
	// shouldnt update data, just uses prev data because it hasnt changed
	AliasUpdate("node1", "jagupdate", "changeddata", "privdata");

}
BOOST_AUTO_TEST_CASE (generate_sendmoneytoalias)
{
	printf("Running generate_sendmoneytoalias...\n");
	GenerateBlocks(5, "node2");
	AliasNew("node2", "sendnode2", "changeddata2");
	UniValue r;
	// get balance of node2 first to know we sent right amount oater
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "getinfo"));
	CAmount balanceBefore = AmountFromValue(find_value(r.get_obj(), "balance"));
	BOOST_CHECK_THROW(CallRPC("node1", "sendtoaddress sendnode2 1.335"), runtime_error);
	GenerateBlocks(1);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "getinfo"));
	balanceBefore += 1.335*COIN;
	CAmount balanceAfter = AmountFromValue(find_value(r.get_obj(), "balance"));
	BOOST_CHECK_EQUAL(balanceBefore, balanceAfter);
}
BOOST_AUTO_TEST_CASE (generate_aliastransfer)
{
	printf("Running generate_aliastransfer...\n");
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	UniValue r;
	string strPubKey1 = AliasNew("node1", "jagnode1", "changeddata1");
	string strPubKey2 = AliasNew("node2", "jagnode2", "changeddata2");
	UniValue pkr = CallRPC("node2", "generatepublickey");
	BOOST_CHECK(pkr.type() == UniValue::VARR);
	const UniValue &resultArray = pkr.get_array();
	string newPubkey = resultArray[0].get_str();	
	AliasTransfer("node1", "jagnode1", "node2", "changeddata1", "pvtdata");

	// xfer an alias that isn't yours
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasupdate jagnode1 changedata1 pvtdata Yes " + newPubkey), runtime_error);

	// trasnfer alias and update it at the same time
	AliasTransfer("node2", "jagnode2", "node3", "changeddata4", "pvtdata");

	// update xferred alias
	AliasUpdate("node2", "jagnode1", "changeddata5", "pvtdata1");

	// retransfer alias
	AliasTransfer("node2", "jagnode1", "node3", "changeddata5", "pvtdata2");

	// xfer an alias to another alias is prohibited
	BOOST_CHECK_THROW(r = CallRPC("node2", "aliasupdate jagnode2 changedata1 pvtdata Yes " + strPubKey1), runtime_error);
	
}
BOOST_AUTO_TEST_CASE (generate_aliassafesearch)
{
	printf("Running generate_aliassafesearch...\n");
	UniValue r;
	GenerateBlocks(1);
	// alias is safe to search
	AliasNew("node1", "jagsafesearch", "pubdata", "privdata", "Yes");
	// not safe to search
	AliasNew("node1", "jagnonsafesearch", "pubdata", "privdata", "No");
	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "On"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "Off"), true);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "Off"), true);

	// shouldn't affect aliasinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagsafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagnonsafesearch"));

	// reverse the rolls
	AliasUpdate("node1", "jagsafesearch", "pubdata", "privdata", "No");
	AliasUpdate("node1", "jagnonsafesearch", "pubdata", "privdata", "Yes");

	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagsafesearch", "On"), false);

	// should only regardless of safesearch
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagnonsafesearch", "On"), true);

	// shouldn't affect aliasinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagsafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagnonsafesearch"));


}

BOOST_AUTO_TEST_CASE (generate_aliasexpiredbuyback)
{
	printf("Running generate_aliasexpiredbuyback...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	
	AliasNew("node1", "aliasexpirebuyback", "somedata", "data");
	// can't renew aliases that aren't expired
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback data"), runtime_error);
	GenerateBlocks(110);
	// expired aliases shouldnt be searchable
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback", "On"), false);
	
	// renew alias and now its searchable
	AliasNew("node1", "aliasexpirebuyback", "somedata1", "data1");
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback", "On"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback", "On"), true);

	GenerateBlocks(110);
	// try to renew alias again second time
	AliasNew("node1", "aliasexpirebuyback", "somedata2", "data2");
	// run the test with node3 offline to test pruning with renewing alias
	StopNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback1 data"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 110"));
	MilliSleep(2500);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback1", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback1", "On"), false);

	StartNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback1", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback1", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node3", "aliasexpirebuyback1", "On"), false);
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "aliasinfo aliasexpirebuyback1"), runtime_error);

	// run the test with node3 offline to test pruning with renewing alias twice
	StopNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback2 data"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 110"));
	MilliSleep(2500);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback2", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback2", "On"), false);
	// renew second time
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback2 data"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 110"));
	MilliSleep(2500);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback2", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback2", "On"), false);
	StartNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasexpirebuyback2", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasexpirebuyback2", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node3", "aliasexpirebuyback2", "On"), false);
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "aliasinfo aliasexpirebuyback2"), runtime_error);

	// steal alias after expiry and original node try to recreate or update should fail
	AliasNew("node1", "aliasexpirebuyback", "somedata", "data");
	GenerateBlocks(110);
	AliasNew("node2", "aliasexpirebuyback", "somedata", "data");
	BOOST_CHECK_THROW(CallRPC("node2", "aliasnew aliasexpirebuyback data"), runtime_error);
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback data"), runtime_error);
	BOOST_CHECK_THROW(CallRPC("node1", "aliasupdate aliasexpirebuyback changedata1 pvtdata"), runtime_error);

	// this time steal the alias and try to recreate at the same time
	GenerateBlocks(110);
	AliasNew("node1", "aliasexpirebuyback", "somedata", "data");
	GenerateBlocks(110);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasnew aliasexpirebuyback data1"));
	GenerateBlocks(5,"node2");
	MilliSleep(2500);
	BOOST_CHECK_THROW(CallRPC("node1", "aliasnew aliasexpirebuyback data2"), runtime_error);
	MilliSleep(2500);
	GenerateBlocks(5);
}

BOOST_AUTO_TEST_CASE (generate_aliasban)
{
	printf("Running generate_aliasban...\n");
	UniValue r;
	GenerateBlocks(10);
	// 2 aliases, one will be banned that is safe searchable other is banned that is not safe searchable
	AliasNew("node1", "jagbansafesearch", "pubdata", "privdata", "Yes");
	AliasNew("node1", "jagbannonsafesearch", "pubdata", "privdata", "No");
	// can't ban on any other node than one that created sysban
	BOOST_CHECK_THROW(AliasBan("node2","jagbansafesearch",SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(AliasBan("node3","jagbansafesearch",SAFETY_LEVEL1), runtime_error);
	// ban both aliases level 1 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",SAFETY_LEVEL1));
	// should only show level 1 banned if safe search filter is not used
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Off"), true);
	// should be able to aliasinfo on level 1 banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"));
	
	// ban both aliases level 2 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",SAFETY_LEVEL2));
	// no matter what filter won't show banned aliases
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Off"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Off"), false);

	// shouldn't be able to aliasinfo on level 2 banned aliases
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"), runtime_error);

	// unban both aliases (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearch",0));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearch",0));
	// safe to search regardless of filter
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "On"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearch", "Off"), true);

	// since safesearch is set to false on this alias, it won't show up in search still
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "On"), false);
	// it will if you are not doing a safe search
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearch", "Off"), true);

	// should be able to aliasinfo on non banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbansafesearch"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo jagbannonsafesearch"));
	
}

BOOST_AUTO_TEST_CASE (generate_aliasbanwithoffers)
{
	printf("Running generate_aliasbanwithoffers...\n");
	UniValue r;
	GenerateBlocks(10);
	// 2 aliases, one will be banned that is safe searchable other is banned that is not safe searchable
	AliasNew("node1", "jagbansafesearchoffer", "pubdata", "privdata", "Yes");
	AliasNew("node1", "jagbannonsafesearchoffer", "pubdata", "privdata", "No");
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearchoffer", "On"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbansafesearchoffer", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearchoffer", "On"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "jagbannonsafesearchoffer", "Off"), true);

	// good case, safe offer with safe alias
	string offerguidsafe1 = OfferNew("node1", "jagbansafesearchoffer", "category", "title", "100", "1.00", "description", "USD", "nocert", true, "0", "location", "Yes");
	// good case, unsafe offer with safe alias
	string offerguidsafe2 = OfferNew("node1", "jagbansafesearchoffer", "category", "title", "100", "1.00", "description", "USD", "nocert", true, "0", "location", "No");
	// good case, unsafe offer with unsafe alias
	string offerguidsafe3 = OfferNew("node1", "jagbannonsafesearchoffer", "category", "title", "100", "1.00", "description", "USD", "nocert", true, "0", "location", "No");

	// safe offer with safe alias should show regardless of safe search
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), true);
	// unsafe offer with safe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);
	// unsafe offer with unsafe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);

	// safe offer with unsafe alias
	string offerguidunsafe = OfferNew("node1", "jagbannonsafesearchoffer", "category", "title", "100", "1.00", "description", "USD", "nocert", true, "0", "location", "Yes");
	// safe offer with unsafe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidunsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidunsafe, "Off"), true);

	// swap safe search fields on the aliases
	AliasUpdate("node1", "jagbansafesearchoffer", "pubdata1", "privatedata1", "No");	
	AliasUpdate("node1", "jagbannonsafesearchoffer", "pubdata1", "privatedata1", "Yes");

	// safe offer with unsafe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), true);
	// unsafe offer with unsafe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);
	// unsafe offer with safe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);

	// keep alive
	OfferUpdate("node1", "jagbansafesearchoffer", offerguidsafe1, "category", "titlenew", "10", "1.00", "descriptionnew", "USD", false, "nocert", true, "location", "Yes");
	OfferUpdate("node1", "jagbansafesearchoffer", offerguidsafe2, "category", "titlenew", "90", "0.15", "descriptionnew", "USD", false, "nocert", true, "location", "No");
	// swap them back and check filters again
	AliasUpdate("node1", "jagbansafesearchoffer", "pubdata1", "privatedata1", "Yes");	
	AliasUpdate("node1", "jagbannonsafesearchoffer", "pubdata1", "privatedata1", "No");

	// safe offer with safe alias should show regardless of safe search
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), true);
	// unsafe offer with safe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);
	// unsafe offer with unsafe alias should show only in safe search off mode
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);

	// unsafe offer with unsafe alias, edit the offer to safe set offer to not safe
	OfferUpdate("node1", "jagbannonsafesearchoffer", offerguidsafe3, "category", "titlenew", "10", "1.00", "descriptionnew", "USD", false, "nocert", true, "location", "No");
	// you won't be able to find it unless in safe search off mode because the alias doesn't actually change
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);	

	// unsafe offer with safe alias, edit to safe offer and change alias to unsafe 
	OfferUpdate("node1", "jagbannonsafesearchoffer", offerguidsafe2, "category", "titlenew", "90", "0.15", "descriptionnew", "USD", false, "nocert", true, "location", "Yes");
	// unsafe offer with unsafe alias should show when safe search off mode only
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);

	// safe offer with safe alias, edit to unsafe offer
	OfferUpdate("node1", "jagbansafesearchoffer", offerguidsafe3, "category", "titlenew", "90", "0.15", "descriptionnew", "USD", false, "nocert", true, "location", "No");

	// keep alive and revert settings
	OfferUpdate("node1", "jagbansafesearchoffer", offerguidsafe1, "category", "titlenew", "10", "1.00", "descriptionnew", "USD", false, "nocert", true, "location", "Yes");
	AliasUpdate("node1", "jagbansafesearchoffer", "pubdata1", "privatedata1", "Yes");	
	AliasUpdate("node1", "jagbannonsafesearchoffer", "pubdata1", "privatedata1", "No");

	// unsafe offer with safe alias should show in safe off mode only
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);

	// revert settings of offers
	OfferUpdate("node1", "jagbansafesearchoffer", offerguidsafe2, "category", "titlenew", "10", "1.00", "descriptionnew", "USD", false, "nocert", true, "location", "No");
	OfferUpdate("node1", "jagbannonsafesearchoffer", offerguidsafe3, "category", "titlenew", "10", "1.00", "descriptionnew", "USD", false, "nocert", true, "location", "No");	

	// ban both aliases level 1 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearchoffer",SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearchoffer",SAFETY_LEVEL1));
	// should only show level 1 banned if safe search filter is used
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);
	// should be able to offerinfo on level 1 banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe1));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe2));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe3));


	// ban both aliases level 2 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearchoffer",SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearchoffer",SAFETY_LEVEL2));
	// no matter what filter won't show banned aliases
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), false);

	// shouldn't be able to offerinfo on level 2 banned aliases
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe1), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe2), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe3), runtime_error);


	// unban both aliases (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbansafesearchoffer",0));
	BOOST_CHECK_NO_THROW(AliasBan("node1","jagbannonsafesearchoffer",0));
	// back to original settings
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "On"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe1, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe2, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe3, "Off"), true);


	// should be able to offerinfo on non banned aliases
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe1));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe2));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe3));
	
}
BOOST_AUTO_TEST_CASE (generate_aliaspruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes

	printf("Running generate_aliaspruning...\n");
	// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
	StopNode("node2");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasprune data"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	// we can find it as normal first
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "Off"), true);
	// then we let the service expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 100"));
	StartNode("node2");
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	// now we shouldn't be able to search it
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune", "Off"), false);
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasinfo aliasprune"));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

	// node2 shouldn't find the service at all (meaning node2 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node2", "aliasinfo aliasprune"), runtime_error);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune", "Off"), false);

	// stop node3
	StopNode("node3");
	// create a new service
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasprune1 data"));
	// make 89 blocks (10 get mined with new)
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 79"));
	MilliSleep(2500);
	// stop and start node1
	StopNode("node1");
	StartNode("node1");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	// give some time to propogate the new blocks across other 2 nodes
	MilliSleep(2500);
	// ensure you can still update before expiry
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate aliasprune1 newdata privdata"));
	// you can search it still on node1/node2
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune1", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune1", "Off"), true);
	// generate 89 more blocks (10 get mined from update)
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 89"));
	MilliSleep(2500);
	// ensure service is still active since its supposed to expire at 100 blocks of non updated services
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate aliasprune1 newdata1 privdata"));
	// you can search it still on node1/node2
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune1", "Off"), true);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune1", "Off"), true);

	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 125"));
	MilliSleep(2500);
	// now it should be expired
	BOOST_CHECK_THROW(CallRPC("node2", "aliasupdate aliasprune1 newdata2 privdata"), runtime_error);
	BOOST_CHECK_EQUAL(AliasFilter("node1", "aliasprune1", "Off"), false);
	BOOST_CHECK_EQUAL(AliasFilter("node2", "aliasprune1", "Off"), false);
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "aliasinfo aliasprune1"));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

	StartNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
	MilliSleep(2500);
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "aliasinfo aliasprune1"), runtime_error);
	BOOST_CHECK_EQUAL(AliasFilter("node3", "aliasprune1", "Off"), false);
}
BOOST_AUTO_TEST_CASE (generate_aliasprunewithoffer)
{
	printf("Running generate_aliasprunewithoffer...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	StopNode("node3");
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasnew aliasprunewithoffer somedata"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasnew aliasprunewithoffer1 somedata"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "aliasnew aliasprunewithoffer2 somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 25"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offernew sysrates.peg aliasprunewithoffer category title 1 0.05 description USD"));
	const UniValue &arr = r.get_array();
	string offerguid = arr[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "escrownew aliasprunewithoffer2 " + offerguid + " 1 message aliasprunewithoffer1"));
	const UniValue &array = r.get_array();
	string escrowguid = array[1].get_str();	
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "escrowrelease " + escrowguid));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "escrowrelease " + escrowguid));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 110"));
	MilliSleep(2500);
	StartNode("node3");
	GenerateBlocks(5, "node3");
}
BOOST_AUTO_TEST_CASE (generate_aliasprunewithcertoffer)
{
	printf("Running generate_aliasprunewithcertoffer...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	StopNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasprunewithcertoffer somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasnew aliasprunewithcertoffer2 somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 20"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certnew aliasprunewithcertoffer jag1 data 0"));
	const UniValue &arr = r.get_array();
	string certguid = arr[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offernew sysrates.peg aliasprunewithcertoffer category title 1 0.05 description USD " + certguid));
	const UniValue &arr1 = r.get_array();
	string certofferguid = arr1[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offernew sysrates.peg aliasprunewithcertoffer category title 1 0.05 description USD"));
	const UniValue &arr2 = r.get_array();
	string offerguid = arr2[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg aliasprunewithcertoffer " + offerguid + " category title 1 0.05 description"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg aliasprunewithcertoffer " + certofferguid + " category title 1 0.05 description USD 0 " + certguid));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offeraccept aliasprunewithcertoffer2 " + certofferguid + " 1 message"));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offeraccept aliasprunewithcertoffer2 " + offerguid + " 1 message"));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 110"));
	MilliSleep(2500);
	StartNode("node3");
	GenerateBlocks(5, "node3");
}

BOOST_AUTO_TEST_CASE (generate_aliasprunewithcert)
{
	printf("Running generate_aliasprunewithcert...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	StopNode("node3");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew aliasprunewithcert somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node2", "aliasnew aliasprunewithcert2 somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certnew aliasprunewithcert jag1 data 0"));
	const UniValue &arr = r.get_array();
	string certguid = arr[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + certguid + " aliasprunewithcert newdata privdata 0"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certtransfer " + certguid + " aliasprunewithcert2"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 110"));
	MilliSleep(2500);
	StartNode("node3");
	GenerateBlocks(5, "node3");
}
BOOST_AUTO_TEST_CASE (generate_aliasexpired)
{
	printf("Running generate_aliasexpired...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	string aliasexpirepubkey = AliasNew("node1", "aliasexpire", "somedata");
	string aliasexpirenode2pubkey = AliasNew("node2", "aliasexpirenode2", "somedata");
	
	GenerateBlocks(50);
	string offerguid = OfferNew("node1", "aliasexpire", "category", "title", "100", "0.01", "description", "USD");
	string certguid = CertNew("node1", "aliasexpire", "certtitle", "certdata", false, "Yes");
	StopNode("node3");
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "escrownew aliasexpirenode2 " + offerguid + " 1 message aliasexpire"));
	const UniValue &array = r.get_array();
	string escrowguid = array[1].get_str();	
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "aliasnew aliasexpire2 somedata"));
	const UniValue &array1 = r.get_array();
	string aliasexpire2pubkey = array1[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);


	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "aliasnew aliasexpire2node2 somedata"));
	const UniValue &array2 = r.get_array();
	string aliasexpire2node2pubkey = array2[1].get_str();	
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 10"));
	MilliSleep(2500);

	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certnew aliasexpire2 certtitle certdata 0"));
	const UniValue &array3 = r.get_array();
	string certgoodguid = array3[1].get_str();	
	// expire aliasexpire and aliasexpirenode2 aliases
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 10"));
	MilliSleep(2500);


	UniValue pkr = CallRPC("node2", "generatepublickey");
	if (pkr.type() != UniValue::VARR)
		throw runtime_error("Could not parse rpc results");

	const UniValue &resultArray = pkr.get_array();
	string pubkey = resultArray[0].get_str();		

	// should fail: alias update on expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "aliasupdate aliasexpirenode2 newdata1 privdata"), runtime_error);
	// should fail: alias transfer from expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "aliasupdate aliasexpirenode2 changedata1 pvtdata Yes " + pubkey), runtime_error);
	// should fail: alias transfer to another alias
	BOOST_CHECK_THROW(CallRPC("node1", "aliasupdate aliasexpire2 changedata1 pvtdata Yes " + aliasexpirenode2pubkey), runtime_error);

	// should fail: link to an expired alias in offer
	BOOST_CHECK_THROW(CallRPC("node2", "offerlink aliasexpirenode2 " + offerguid + " 5 newdescription"), runtime_error);
	// should fail: generate an offer using expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "offernew sysrates.peg aliasexpirenode2 category title 1 0.05 description USD nocert 0 1"), runtime_error);

	// should fail: send message from expired alias to expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "messagenew subject title aliasexpirenode2 aliasexpirenode2"), runtime_error);
	// should fail: send message from expired alias to non-expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "messagenew subject title aliasexpirenode2 aliasexpire"), runtime_error);
	// should fail: send message from non-expired alias to expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "messagenew subject title aliasexpire aliasexpirenode2"), runtime_error);

	// should fail: new escrow with expired arbiter alias
	BOOST_CHECK_THROW(CallRPC("node2", "escrownew aliasexpire2node2 " + offerguid + " 1 message aliasexpirenode2"), runtime_error);
	// should fail: new escrow with expired alias
	BOOST_CHECK_THROW(CallRPC("node2", "escrownew aliasexpirenode2 " + offerguid + " 1 message aliasexpire"), runtime_error);

	// keep alive for later calls
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate aliasexpire2 newdata1 privdata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1","generate 5"));
	MilliSleep(2500);
	
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + certgoodguid + " aliasexpire2 newdata privdata 0"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg aliasexpire " + offerguid + " category title 100 0.05 description"));
	// expire the escrow
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 30"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + certguid + " aliasexpire jag1 data 0"));
	BOOST_CHECK_NO_THROW(CallRPC("node1","generate 35"));
	MilliSleep(2500);

	StartNode("node3");
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
	MilliSleep(2500); 
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate aliasexpire2 newdata1 privdata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	MilliSleep(2500);
	// ensure node3 can see (not pruned) expired escrows that aren't complete or refunded yet
	BOOST_CHECK_NO_THROW(CallRPC("node3", "escrowinfo " + escrowguid));
	// and node2
	BOOST_CHECK_NO_THROW(CallRPC("node2", "escrowinfo " + escrowguid));
	// not able to release an escrow with expired aliases
	BOOST_CHECK_THROW(CallRPC("node2", "escrowrelease " + escrowguid), runtime_error);
	// this will recreate the alias and give it a new pubkey.. we need to use the old pubkey to sign the multisig, the escrow rpc call must check for the right pubkey
	BOOST_CHECK_EQUAL(aliasexpirenode2pubkey, AliasNew("node2", "aliasexpirenode2", "somedata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + certgoodguid + " aliasexpire2 newdata privdata 0"));
	// able to release and claim release on escrow with non-expired aliases with new pubkeys
	EscrowRelease("node2", escrowguid);	 
	EscrowClaimRelease("node1", escrowguid); 

	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 25"));
	MilliSleep(2500);
	// should fail: update cert with expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "certupdate " + certguid + " aliasexpire jag1 data 0"), runtime_error);
	// should fail: xfer an cert with expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "certtransfer " + certguid + " aliasexpire2"), runtime_error);
	// should fail: xfer an cert to an expired alias even though transferring cert is good
	BOOST_CHECK_THROW(CallRPC("node1", "certtransfer " + certgoodguid + " aliasexpire"), runtime_error);


	// should pass: confirm that the transferring cert is good by transferring to a good alias
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certtransfer " + certgoodguid + " aliasexpirenode2"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certgoodguid));
	// ensure it got transferred
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "alias").get_str(), "aliasexpirenode2");

	GenerateBlocks(110);
	// should fail: generate a cert using expired alias
	BOOST_CHECK_THROW(CallRPC("node1", "certnew aliasexpire2 jag1 data 1"), runtime_error);
}
BOOST_AUTO_TEST_SUITE_END ()