#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpcserver.h"
#include "alias.h"
#include "feedback.h"
#include <boost/test/unit_test.hpp>
BOOST_GLOBAL_FIXTURE( SyscoinTestingSetup );

BOOST_FIXTURE_TEST_SUITE (syscoin_offer_tests, BasicSyscoinTestingSetup)


BOOST_AUTO_TEST_CASE (generate_offernew)
{
	printf("Running generate_offernew...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias1", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias1", "category", "title", "100", "0.05", "description", "USD");
	// by default offers are set to private and not searchable
	BOOST_CHECK_EQUAL(OfferFilter("node1", "", "On"), false);
	// direct search should work
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguid, "On"), true);

	// should fail: generate an offer with unknown alias
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg fooalias category title 100 0.05 description USD"), runtime_error);

	// should fail: generate an offer with negative quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg selleralias1 category title -2 0.05 description USD"), runtime_error);

	// should fail: generate an offer too-large category
	string s256bytes = "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg selleralias1 " + s256bytes + " title 100 0.05 description USD"), runtime_error);	

	// should fail: generate an offer too-large title
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg selleralias1 category " + s256bytes + " 100 0.05 description USD"), runtime_error);	

	// should fail: generate an offer too-large description
	string s1024bytes =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg selleralias1 category title 100 0.05 " + s1024bytes + " USD"), runtime_error);

	// should fail: generate an offer with invalid currency
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg selleralias1 category title 100 0.05 description ZZZ"), runtime_error);
}

BOOST_AUTO_TEST_CASE (generate_certoffernew)
{
	printf("Running generate_certoffernew...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias", "node1aliasdata");
	AliasNew("node2", "node2alias", "node2aliasdata");

	string certguid1  = CertNew("node1", "node1alias", "title", "data");
	string certguid1a = CertNew("node1", "node1alias", "title", "data");
	string certguid2  = CertNew("node2", "node2alias", "title", "data");

	// generate a good cert offer
	string offerguid = OfferNew("node1", "node1alias", "category", "title", "1", "0.05", "description", "USD", certguid1);

	// should fail: generate a cert offer using a quantity greater than 1
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias category title 2 0.05 description USD " + certguid1a), runtime_error);

	// should fail: generate a cert offer using a zero quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias category title 0 0.05 description USD " + certguid1a), runtime_error);

	// should fail: generate a cert offer using an unlimited quantity
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias category title -1 0.05 description USD " + certguid1a), runtime_error);

	// should fail: generate a cert offer using a cert guid you don't own
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias category title 1 0.05 description USD " + certguid2), runtime_error);	

	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias category title 1 0.05 description USD " + certguid2), runtime_error);	

	// should fail: generate a cert offer if accepting only BTC
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias category title 1 0.05 description USD " + certguid1a + " 0 1"), runtime_error);

	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias category title 1 0.05 description USD " + certguid1a + " 0 1"), runtime_error);
	// should fail: generate a cert offer using different public keys for cert and alias
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew node1alias category title 1 0.05 description USD " + certguid1a + " 0 0 1"), runtime_error);


}
BOOST_AUTO_TEST_CASE (generate_offerwhitelists)
{
	printf("Running generate_offerwhitelists...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "sellerwhitelistalias", "changeddata1");
	AliasNew("node2", "selleraddwhitelistalias", "changeddata1");
	AliasNew("node2", "selleraddwhitelistalias1", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "sellerwhitelistalias", "category", "title", "100", "10.00", "description", "SYS", "nocert", false);
	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "5");
	BOOST_CHECK_THROW(CallRPC("node1", "offeraddwhitelist " + offerguid + " selleraddwhitelistalias 5"), runtime_error);
	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias1", "6");
	// remove from whitelist
	OfferRemoveWhitelist("node1", offerguid, "selleraddwhitelistalias");
	BOOST_CHECK_THROW(CallRPC("node1", "offerremovewhitelist " + offerguid + " selleraddwhitelistalias"), runtime_error);

	AliasUpdate("node1", "sellerwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias1", "changeddata2", "privdata2");

	// add to whitelist
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "4");
	OfferClearWhitelist("node1", offerguid);
	BOOST_CHECK_THROW(CallRPC("node1", "offerclearwhitelist " + offerguid), runtime_error);

	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "6");

	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");

	AliasUpdate("node1", "sellerwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias", "changeddata2", "privdata2");
	AliasUpdate("node2", "selleraddwhitelistalias1", "changeddata2", "privdata2");

	OfferRemoveWhitelist("node1", offerguid, "selleraddwhitelistalias");

	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias", "1");
	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");
	OfferAddWhitelist("node1", offerguid, "selleraddwhitelistalias1", "2");


	OfferAccept("node1", "node2", "selleraddwhitelistalias1", offerguid, "1", "message");
	OfferClearWhitelist("node1", offerguid);


}
BOOST_AUTO_TEST_CASE (generate_offernew_linkedoffer)
{
	printf("Running generate_offernew_linkedoffer...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias5", "changeddata1");
	AliasNew("node2", "selleralias6", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias5", "category", "title", "100", "10.00", "description", "USD", "nocert", false);
	string lofferguid = OfferLink("node2", "selleralias6", offerguid, "5", "newdescription");
	
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offerinfo " + lofferguid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), "10.50");

	// generate a cert offer using a negative percentage bigger than discount
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " -5 newdescription"), runtime_error);	


	// should fail: generate a cert offer using too-large pergentage
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " 101 newdescription"), runtime_error);	

	// should fail: generate an offerlink with too-large description
	string s1024bytes =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias6 " + offerguid + " 5 " + s1024bytes), runtime_error);

	// ensure the alias doesn't expire
	GenerateBlocks(40);
	AliasUpdate("node2", "selleralias6", "changeddata1", "privdata");
	// let the offer expire
	GenerateBlocks(51);
	// should fail: try to link against an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerlink selleralias6 " + offerguid + " 5 newdescription"), runtime_error);
	
}

BOOST_AUTO_TEST_CASE (generate_offernew_linkedofferexmode)
{
	printf("Running generate_offernew_linkedofferexmode...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias8", "changeddata1");
	AliasNew("node2", "selleralias9", "changeddata1");

	// generate a good offer in exclusive mode
	string offerguid = OfferNew("node1", "selleralias8", "category", "title", "100", "0.05", "description", "USD");

	// should fail: attempt to create a linked offer for an exclusive mode product without being on the whitelist
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink selleralias9 " + offerguid + " 5 newdescription"), runtime_error);

	// should succeed: offer seller adds affiliate to whitelist
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offeraddwhitelist " + offerguid + " selleralias9 10"));
	GenerateBlocks(10);

	// should succeed: attempt to create a linked offer for an exclusive mode product while being on the whitelist
	OfferLink("node2", "selleralias9", offerguid, "5", "newdescription");
}

BOOST_AUTO_TEST_CASE (generate_offernew_linkedlinkedoffer)
{
	printf("Running generate_offernew_linkedlinkedoffer...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias12", "changeddata1");
	AliasNew("node2", "selleralias13", "changeddata1");
	AliasNew("node3", "selleralias14", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias12", "category", "title", "100", "0.05", "description", "USD", "nocert", false);
	string lofferguid = OfferLink("node2", "selleralias13", offerguid, "5", "newdescription");

	// should fail: try to generate a linked offer with a linked offer
	BOOST_CHECK_THROW(r = CallRPC("node3", "offerlink selleralias14 " + lofferguid + " 5 newdescription"), runtime_error);

}

BOOST_AUTO_TEST_CASE (generate_offerupdate)
{
	printf("Running generate_offerupdate...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias2", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias2", "category", "title", "100", "0.05", "description", "USD");

	// perform a valid update
	OfferUpdate("node1", "selleralias2", offerguid, "category", "titlenew", "90", "0.15", "descriptionnew");

	// should fail: offer cannot be updated by someone other than owner
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerupdate sysrates.peg selleralias2 " + offerguid + " category title 90 0.15 description"), runtime_error);


	// should fail: generate an offer with unknown alias
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate sysrates.peg fooalias " + offerguid + " category title 90 0.15 description"), runtime_error);

	// should fail: generate an offer too-large category
	string s256bytes =   "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate sysrates.peg selleralias2 " + offerguid + " " + s256bytes + " title 90 0.15 description"), runtime_error);	

	// should fail: generate an offer too-large title
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate sysrates.peg selleralias2 " + offerguid + " category " + s256bytes + " 90 0.15 description"), runtime_error);	

	// should fail: generate an offer too-large description
	string s1024bytes =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate sysrates.peg selleralias2 " + offerguid + " category title 90 0.15 " + s1024bytes), runtime_error);

}

BOOST_AUTO_TEST_CASE (generate_offerupdate_editcurrency)
{
	printf("Running generate_offerupdate_editcurrency...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleraliascurrency", "changeddata1");
	AliasNew("node2", "buyeraliascurrency", "changeddata2");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleraliascurrency", "category", "title", "100", "0.05", "description", "USD");
	// accept and confirm payment is accurate with usd
	string acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "2", "message");
	UniValue acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	CAmount nTotal = find_value(acceptRet, "systotal").get_int64();
	// 2690.1 SYS/USD
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(2*0.05*2690.1));

	// perform a valid update
	OfferUpdate("node1", "selleraliascurrency", offerguid, "category", "titlenew", "90", "0.15", "descriptionnew", "CAD");
	// accept and confirm payment is accurate with cad
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "3", "message");
	acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 2698.0 SYS/CAD
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(3*0.15*2698.0));

	AliasUpdate("node1", "selleraliascurrency", "changeddata2", "privdata2");
	AliasUpdate("node2", "buyeraliascurrency", "changeddata2", "privdata2");


	OfferUpdate("node1", "selleraliascurrency", offerguid, "category", "titlenew", "90", "1.00", "descriptionnew", "SYS");
	// accept and confirm payment is accurate with sys
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "3", "message");
	acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 1 SYS/SYS
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(3));

	OfferUpdate("node1", "selleraliascurrency", offerguid, "category", "titlenew", "90", "0.00001000", "descriptionnew", "BTC");
	// accept and confirm payment is accurate with btc
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "4", "message");
	acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// 100000.0 SYS/BTC
	BOOST_CHECK_EQUAL(nTotal + COIN, AmountFromValue(4*0.00001000*100000.0));

	// try to update currency and accept in same block, ensure payment uses old currency not new
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg selleraliascurrency " + offerguid + " category title 90 0.2 desc EUR"));
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offeraccept buyeraliascurrency " + offerguid + " 10 message"));
	const UniValue &arr = r.get_array();
	acceptguid = arr[1].get_str();
	GenerateBlocks(2);
	GenerateBlocks(3);
	GenerateBlocks(5, "node2");
	acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	// still used BTC conversion amount
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(10*0.00001000*100000.0));
	// 2695.2 SYS/EUR
	acceptguid = OfferAccept("node1", "node2", "buyeraliascurrency", offerguid, "1", "message");
	acceptRet = FindOfferAccept("node2", offerguid, acceptguid);
	nTotal = find_value(acceptRet, "systotal").get_int64();
	BOOST_CHECK_EQUAL(nTotal, AmountFromValue(1*0.2*2695.2));

	// linked offer with root and linked offer changing currencies

	// escrow offer with currency updated before release

	// directbtc


}
BOOST_AUTO_TEST_CASE (generate_offeraccept)
{
	printf("Running generate_offeraccept...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias3", "somedata");
	AliasNew("node2", "buyeralias3", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias3", "category", "title", "100", "0.01", "description", "USD");

	// perform a valid accept
	string acceptguid = OfferAccept("node1", "node2", "buyeralias3", offerguid, "1", "message");
	// should fail: generate an offer accept with too-large message
	string s1024bytes =   "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 1 " + s1024bytes), runtime_error);

	// perform an accept on more items than available
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 100 message"), runtime_error);

	// perform an accept on negative quantity
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " -1 message"), runtime_error);

	// perform an accept on zero quantity
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias3 " + offerguid + " 0 message"), runtime_error);


}
BOOST_AUTO_TEST_CASE (generate_linkedaccept)
{
	printf("Running generate_linkedaccept...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1aliaslinked", "node1aliasdata");
	AliasNew("node2", "node2aliaslinked", "node2aliasdata");
	AliasNew("node3", "node3aliaslinked", "node2aliasdata");

	string offerguid = OfferNew("node1", "node1aliaslinked", "category", "title", "10", "0.05", "description", "USD", "nocert", false);
	string lofferguid = OfferLink("node2", "node2aliaslinked", offerguid, "3", "newdescription");

	OfferAccept("node1", "node3", "node3aliaslinked", lofferguid, "6", "message", "node2");
}
BOOST_AUTO_TEST_CASE (generate_cert_linkedaccept)
{
	printf("Running generate_cert_linkedaccept...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias", "node1aliasdata");
	AliasNew("node2", "node2alias", "node2aliasdata");
	AliasNew("node3", "node3alias", "node2aliasdata");

	string certguid  = CertNew("node1", "node1alias", "title", "data");
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguid));
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");	
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == "node1alias");
	// generate a good cert offer
	string offerguid = OfferNew("node1", "node1alias", "category", "title", "1", "0.05", "description", "USD", certguid, false);
	string lofferguid = OfferLink("node2", "node2alias", offerguid, "5", "newdescription");

	AliasUpdate("node1", "node1alias", "changeddata2", "privdata2");
	AliasUpdate("node2", "node2alias", "changeddata2", "privdata2");
	AliasUpdate("node3", "node3alias", "changeddata3", "privdata3");
	OfferAccept("node1", "node3", "node3alias", lofferguid, "1", "message", "node2");
	GenerateBlocks(5, "node1");
	GenerateBlocks(5, "node3");
	BOOST_CHECK_NO_THROW(r = CallRPC("node3", "certinfo " + certguid));
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "alias").get_str(), "node3alias");
}
BOOST_AUTO_TEST_CASE (generate_offeracceptfeedback)
{
	printf("Running generate_offeracceptfeedback...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleraliasfeedback", "somedata");
	AliasNew("node2", "buyeraliasfeedback", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleraliasfeedback", "category", "title", "100", "0.01", "description", "USD");

	// perform a valid accept
	string acceptguid = OfferAccept("node1", "node2", "buyeraliasfeedback", offerguid, "1", "message");
	// seller leaves feedback first
	OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller", "1", FEEDBACKSELLER, true);
	// seller can leave feedback twice in a row
	OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller", "1", FEEDBACKSELLER, false);

	// then buyer can leave feedback
	OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer", "5", FEEDBACKBUYER, true);
	// can leave feedback twice in  arow
	OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer2", "5", FEEDBACKBUYER, false);

	// create up to 10 replies each
	for(int i =0;i<8;i++)
	{
		// keep alive
		OfferUpdate("node1", "selleraliasfeedback", offerguid, "category", "titlenew", "90", "0.01", "descriptionnew", "USD");
		// seller can reply but not rate
		OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller1", "2", FEEDBACKSELLER, false);

		// buyer can reply but not rate
		OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer1", "3", FEEDBACKBUYER, false);
		
	}
	string offerfeedbackstr = "offeracceptfeedback " + offerguid + " " + acceptguid + " testfeedback 1";
	// now you can't leave any more feedback as a seller
	BOOST_CHECK_THROW(r = CallRPC("node1", offerfeedbackstr), runtime_error);

	// perform a valid accept
	acceptguid = OfferAccept("node1", "node2", "buyeraliasfeedback", offerguid, "1", "message");
	GenerateBlocks(5, "node2");
	// this time buyer leaves feedback first
	OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, true);
	// buyer can leave feedback three times in a row
	OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, false);
	OfferAcceptFeedback("node2", offerguid, acceptguid, "feedbackbuyer", "1", FEEDBACKBUYER, false);

	// then seller can leave feedback
	OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller", "5", FEEDBACKSELLER, true);
	OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller2", "4", FEEDBACKSELLER, false);
	OfferAcceptFeedback("node1", offerguid, acceptguid, "feedbackseller2", "4", FEEDBACKSELLER, false);
}
BOOST_AUTO_TEST_CASE (generate_offerexpired)
{
	printf("Running generate_offerexpired...\n");
	UniValue r;
	
	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias4", "somedata");
	AliasNew("node2", "buyeralias4", "somedata");

	// generate a good offer
	string offerguid = OfferNew("node1", "selleralias4", "category", "title", "100", "0.01", "description", "USD");
	GenerateBlocks(40);
	// ensure aliases dont't expire
	AliasUpdate("node1", "selleralias4", "selleralias4", "data1");
	AliasUpdate("node2", "buyeralias4", "buyeralias4", "data1");
	// this will expire the offer
	GenerateBlocks(65);

	// should fail: perform an accept on expired offer
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept buyeralias4 " + offerguid + " 1 message"), runtime_error);

	GenerateBlocks(5);
	// should fail: offer update on an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerupdate sysrates.peg selleralias4 " + offerguid + " category title 90 0.15 description"), runtime_error);
	
	// should fail: link to an expired offer
	BOOST_CHECK_THROW(r = CallRPC("node2", "offerlink buyeralias4 " + offerguid + " 5 newdescription"), runtime_error);	
	

}

BOOST_AUTO_TEST_CASE (generate_offerexpiredexmode)
{
	printf("Running generate_offerexpiredexmode...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "selleralias10", "changeddata1");
	AliasNew("node2", "selleralias11", "changeddata1");

	// generate a good offer in exclusive mode
	string offerguid = OfferNew("node1", "selleralias10", "category", "title", "100", "0.05", "description", "USD", "nocert", true);

	// should succeed: offer seller adds affiliate to whitelist
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offeraddwhitelist " + offerguid + " selleralias11 10"));
	GenerateBlocks(40);
	// ensure alias doesn't expire
	AliasUpdate("node1", "selleralias10", "selleralias10", "data1");
	AliasUpdate("node2", "selleralias11", "selleralias11", "data1");
	// this will expire the offer
	GenerateBlocks(51);

	// should fail: remove whitelist item from expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerremovewhitelist " + offerguid + " selleralias11"), runtime_error);
	// should fail: clear whitelist from expired offer
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerclearwhitelist " + offerguid), runtime_error);

}

BOOST_AUTO_TEST_CASE (generate_certofferexpired)
{
	printf("Running generate_certofferexpired...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node1", "node1alias2", "node1aliasdata");
	AliasNew("node2", "node2alias2", "node2aliasdata");

	string certguid  = CertNew("node1", "node1alias2", "title", "data");
	string certguid2  = CertNew("node1", "node1alias2", "title", "data");

	// this leaves 50 blocks remaining before cert expires
	GenerateBlocks(40);

	// generate a good cert offer
	string offerguid = OfferNew("node1", "node1alias2", "category", "title", "1", "0.05", "description", "USD", certguid);

	// ensure aliases don't expire
	AliasUpdate("node1", "node1alias2", "node1aliasdata1", "data2");
	AliasUpdate("node2", "node2alias2", "node2aliasdata1", "data2");
	// updates the offer so it won't expire, and doesn't update cert linked to offer so we can have offer linked with expired cert
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offeraccept node2alias2 " + offerguid + " 1 message"));
	GenerateBlocks(10);
	// this expires the cert but not the offer
	GenerateBlocks(55);
	MilliSleep(2500);

	GenerateBlocks(15, "node2");
	MilliSleep(2500);
	// should fail: offer accept on offer with expired/transferred cert
	BOOST_CHECK_THROW(r = CallRPC("node2", "offeraccept node2alias2 " + offerguid + " 1 message"), runtime_error);
	// should fail: generate a cert offer using an expired cert
	BOOST_CHECK_THROW(r = CallRPC("node1", "offernew sysrates.peg node1alias2 category title 1 0.05 description USD " + certguid2), runtime_error);
}

BOOST_AUTO_TEST_CASE (generate_offerlink_offlinenode)
{
	printf("Running generate_offerlink_offlinenode...\n");
	UniValue r;

	GenerateBlocks(5);
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");

	AliasNew("node2", "selleralias15", "changeddata1");
	AliasNew("node1", "selleralias16", "changeddata1");

	// generate a good offer
	string offerguid = OfferNew("node2", "selleralias15", "category", "title", "100", "10.00", "description", "USD", "nocert", false);

	// stop node2 and link offer on node1 while node2 is offline
	StopNode("node2");
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerlink selleralias16 " + offerguid + " 5 newdescription"));
	const UniValue &arr = r.get_array();
	string lofferguid = arr[1].get_str();
	// generate 10 blocks on node1
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "generate 10"));

	// startup node1 again and see that it has linked offer and its right price (with markup)
	StartNode("node2");
	GenerateBlocks(10);
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offerinfo " + lofferguid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), "10.50");
}
BOOST_AUTO_TEST_CASE (generate_offersafesearch)
{
	printf("Running generate_offersafesearch...\n");
	UniValue r;
	GenerateBlocks(1);
	// make sure alias doesn't expire 
	AliasUpdate("node2", "selleralias15", "changeddata2", "privdata2");
	// offer is safe to search
	string offerguidsafe = OfferNew("node2", "selleralias15", "category", "title", "100", "10.00", "description", "USD", "nocert", true, "0", "location", "Yes");
	// not safe to search
	string offerguidnotsafe = OfferNew("node2", "selleralias15", "category", "title", "100", "10.00", "description", "USD", "nocert", true, "0", "location", "No");
	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "On"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "Off"), true);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "Off"), true);

	// shouldn't affect offerinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));

	// reverse the rolls
	OfferUpdate("node2", "selleralias15", offerguidsafe, "category", "titlenew", "90", "0.15", "descriptionnew", "USD", false, "nocert", false, "location", "No");
	OfferUpdate("node2", "selleralias15", offerguidnotsafe, "category", "titlenew", "90", "0.15", "descriptionnew", "USD", false, "nocert", false, "location", "Yes");


	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "On"), false);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "On"), true);

	// shouldn't affect offerinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));


}
BOOST_AUTO_TEST_CASE (generate_offerban)
{
	printf("Running generate_offerban...\n");
	UniValue r;
	GenerateBlocks(1);
	// make sure alias doesn't expire 
	AliasUpdate("node2", "selleralias15", "changeddata2", "privdata2");
	// offer is safe to search
	string offerguidsafe = OfferNew("node2", "selleralias15", "category", "title", "100", "10.00", "description", "USD", "nocert", true, "0", "location", "Yes");
	// not safe to search
	string offerguidnotsafe = OfferNew("node2", "selleralias15", "category", "title", "100", "10.00", "description", "USD", "nocert", true, "0", "location", "No");
	// can't ban on any other node than one that created sysban
	BOOST_CHECK_THROW(OfferBan("node2",offerguidnotsafe,SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(OfferBan("node3",offerguidsafe,SAFETY_LEVEL1), runtime_error);
	// ban both offers level 1 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,SAFETY_LEVEL1));
	// should only show level 1 banned if safe search filter is not used
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "Off"), true);
	// should be able to offerinfo on level 1 banned offers
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));
	
	// ban both offers level 2 (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,SAFETY_LEVEL2));
	// no matter what filter won't show banned offers
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "Off"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "Off"), false);

	// shouldn't be able to offerinfo on level 2 banned offers
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe), runtime_error);

	// unban both offers (only owner of syscategory can do this)
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidsafe,0));
	BOOST_CHECK_NO_THROW(OfferBan("node1",offerguidnotsafe,0));
	// safe to search regardless of filter
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "On"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidsafe, "Off"), true);

	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node1", offerguidnotsafe, "Off"), true);

	// should be able to offerinfo on non banned offers
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + offerguidnotsafe));
	
}
BOOST_AUTO_TEST_CASE (generate_offerpruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes

	printf("Running generate_offerpruning...\n");
	AliasNew("node1", "pruneoffer", "changeddata1");
	// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
	StopNode("node2");
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offernew sysrates.peg pruneoffer category title 1 0.05 description USD"));
	const UniValue &arr = r.get_array();
	string guid = arr[1].get_str();
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
	// we can find it as normal first
	BOOST_CHECK_EQUAL(OfferFilter("node1", guid, "Off"), true);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
	MilliSleep(2500);
	// make sure our offer alias doesn't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate pruneoffer newdata privdata"));
	// then we let the service expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
	StartNode("node2");
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	// now we shouldn't be able to search it
	BOOST_CHECK_EQUAL(OfferFilter("node1", guid, "Off"), false);
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offerinfo " + guid));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

	// shouldnt be pruned yet because alias pruneoffer isn't expired
	BOOST_CHECK_NO_THROW(CallRPC("node2", "offerinfo " + guid));


	// stop node3
	StopNode("node3");
	// make sure our offer alias doesn't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate pruneoffer newdata privdata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 4"));
	MilliSleep(2500);
	// create a new service
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "offernew sysrates.peg pruneoffer category title 1 0.05 description USD"));
	const UniValue &arr1 = r.get_array();
	string guid1 = arr1[1].get_str();
	// make 89 blocks (10 get mined with new)
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 75"));
	MilliSleep(2500);
	// stop and start node1
	StopNode("node1");
	StartNode("node1");
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 3"));
	// give some time to propogate the new blocks across other 2 nodes
	MilliSleep(2500);
	// ensure you can still update before expiry
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg pruneoffer " + guid1 + " category title 1 0.05 description"));
	// you can search it still on node1/node2
	BOOST_CHECK_EQUAL(OfferFilter("node1", guid1, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node2", guid1, "Off"), true);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 2"));
	MilliSleep(2500);
	// make sure our offer alias doesn't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate pruneoffer newdata privdata"));
	// generate 89 more blocks (10 get mined from update)
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 89"));
	MilliSleep(2500);
	// ensure service is still active since its supposed to expire at 100 blocks of non updated services
	BOOST_CHECK_NO_THROW(CallRPC("node1", "offerupdate sysrates.peg pruneoffer " + guid1 + " category title 1 0.05 description"));
	// you can search it still on node1/node2
	BOOST_CHECK_EQUAL(OfferFilter("node1", guid1, "Off"), true);
	BOOST_CHECK_EQUAL(OfferFilter("node2", guid1, "Off"), true);
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 55"));
	MilliSleep(2500);
	// make sure our offer alias doesn't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate pruneoffer newdata privdata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 55"));
	MilliSleep(2500);
	// make sure our offer alias doesn't expire
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate pruneoffer newdata privdata"));
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 60"));
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
	MilliSleep(2500);
	// now it should be expired
	BOOST_CHECK_THROW(CallRPC("node1", "offerupdate sysrates.peg pruneoffer " + guid1 + " category title 1 0.05 description"), runtime_error);
	BOOST_CHECK_EQUAL(OfferFilter("node1", guid1, "Off"), false);
	BOOST_CHECK_EQUAL(OfferFilter("node2", guid1, "Off"), false);
	// and it should say its expired
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "offerinfo " + guid1));
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	
	// expire the alias and offer now so it should be pruned
	BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
	StartNode("node3");
	MilliSleep(2500);
	BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
	MilliSleep(2500);
	// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
	BOOST_CHECK_THROW(CallRPC("node3", "offerinfo " + guid1), runtime_error);
	BOOST_CHECK_EQUAL(OfferFilter("node3", guid1, "Off"), false);

}

BOOST_AUTO_TEST_SUITE_END ()