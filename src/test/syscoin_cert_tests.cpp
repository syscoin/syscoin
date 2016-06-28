#include "test/test_syscoin_services.h"
#include "utiltime.h"
#include "rpcserver.h"
#include "alias.h"
#include <boost/test/unit_test.hpp>
BOOST_FIXTURE_TEST_SUITE (syscoin_cert_tests, BasicSyscoinTestingSetup)

BOOST_AUTO_TEST_CASE (generate_big_certdata)
{
	printf("Running generate_big_certdata...\n");
	GenerateBlocks(5);
	AliasNew("node1", "jagcertbig1", "data");
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";
	// 1024 bytes long
	string baddata =  "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsdz";
	string guid = CertNew("node1", "jagcertbig1", "jag", gooddata);
	// unencrypted we are allowed up to 1108 bytes
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certnew jagcertbig1 jag1 " + baddata + " 0"));
	// but unencrypted 1024 bytes should cause us to trip 1108 bytes once encrypted
	BOOST_CHECK_THROW(CallRPC("node1", "certnew jagcertbig1 jag1 " + baddata + " 1"), runtime_error);
	// update cert with long data, public (good) vs private (bad)
	BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + guid + " jag1 " + baddata + " 0"));
	// trying to update the public cert to a private one with 1024 bytes should fail aswell
	BOOST_CHECK_THROW(CallRPC("node1", "certupdate " + guid + " jag1 " + baddata + " 1"), runtime_error);

}
BOOST_AUTO_TEST_CASE (generate_big_certtitle)
{
	printf("Running generate_big_certtitle...\n");
	GenerateBlocks(5);
	AliasNew("node1", "jagcertbig2", "data");
	// 255 bytes long
	string goodtitle = "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfdd";
	// 1023 bytes long
	string gooddata = "asdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfasdfasdfsadfsadassdsfsdfsdfsdfsdfsdsdfssdsfsdfsdfsdfsdfsdsdfdfsdfsdfsdfsd";	
	// 256 bytes long
	string badtitle =   "SfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsfDsdsdsdsfsfsdsfsdsfdsfsdsfdsfsdsfsdSfsdfdfsdsfSfsdfdfsdsDfdfddz";
	CertNew("node1", "jagcertbig2", goodtitle, "a");
	BOOST_CHECK_THROW(CallRPC("node1", "certnew jagcertbig2 " + badtitle + " 3d"), runtime_error);
}
BOOST_AUTO_TEST_CASE (generate_certupdate)
{
	printf("Running generate_certupdate...\n");
	AliasNew("node1", "jagcertupdate", "data");
	string guid = CertNew("node1", "jagcertupdate", "title", "data");
	// update an cert that isn't yours
	BOOST_CHECK_THROW(CallRPC("node2", "certupdate " + guid + " title data 0"), runtime_error);
	CertUpdate("node1", guid, "changedtitle", "changeddata");
	// shouldnt update data, just uses prev data because it hasnt changed
	CertUpdate("node1", guid, "changedtitle", "changeddata");

}
BOOST_AUTO_TEST_CASE (generate_certtransfer)
{
	printf("Running generate_certtransfer...\n");
	GenerateBlocks(5, "node2");
	GenerateBlocks(5, "node3");
	AliasNew("node1", "jagcert1", "changeddata1");
	AliasNew("node2", "jagcert2", "changeddata2");
	AliasNew("node3", "jagcert3", "changeddata3");
	string guid, pvtguid, certtitle, certdata;
	certtitle = "certtitle";
	certdata = "certdata";
	guid = CertNew("node1", "jagcert1", certtitle, certdata);
	// private cert
	pvtguid = CertNew("node1", "jagcert1", certtitle, certdata);
	CertUpdate("node1", pvtguid, certtitle, certdata, true);
	UniValue r;
	CertTransfer("node1", guid, "jagcert2");
	CertTransfer("node1", pvtguid, "jagcert3");
	// it got xferred to right person
	BOOST_CHECK_NO_THROW(r = CallRPC("node2", "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == "jagcert2");
	BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == certdata);

	BOOST_CHECK_NO_THROW(r = CallRPC("node3", "certinfo " + pvtguid));
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == "jagcert3");
	BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == certdata);
	// xfer an cert that isn't yours
	BOOST_CHECK_THROW(CallRPC("node1", "certtransfer " + guid + " jagcert2"), runtime_error);

	// update xferred cert
	certdata = "newdata";
	certtitle = "newtitle";
	CertUpdate("node2", guid, certtitle, certdata);

	// retransfer cert
	CertTransfer("node2", guid, "jagcert3");
}
BOOST_AUTO_TEST_CASE (generate_certsafesearch)
{
	printf("Running generate_certsafesearch...\n");
	UniValue r;
	GenerateBlocks(1);
	AliasNew("node1", "jagsafesearch1", "changeddata1");
	// cert is safe to search
	string certguidsafe = CertNew("node1", "jagsafesearch1", "certtitle", "certdata", false, "Yes");
	// not safe to search
	string certguidnotsafe = CertNew("node1", "jagsafesearch1", "certtitle", "certdata", false, "No");
	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "On"), true);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "Off"), true);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "Off"), true);

	// shouldn't affect certinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));

	// reverse the rolls
	CertUpdate("node1", certguidsafe, "certtitle", "certdata", false, "No");
	CertUpdate("node1", certguidnotsafe,  "certtitle", "certdata", false, "Yes");

	// should include result in both safe search mode on and off
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "Off"), true);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "On"), false);

	// should only show up if safe search is off
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "Off"), true);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "On"), true);

	// shouldn't affect certinfo
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));


}
BOOST_AUTO_TEST_CASE (generate_certban)
{
	printf("Running generate_certban...\n");
	UniValue r;
	GenerateBlocks(1);
	// cert is safe to search
	string certguidsafe = CertNew("node1", "jagsafesearch1", "certtitle", "certdata", false, "Yes");
	// not safe to search
	string certguidnotsafe = CertNew("node1", "jagsafesearch1", "certtitle", "certdata", false, "No");
	// can't ban on any other node than one that created SYS_BAN
	BOOST_CHECK_THROW(CertBan("node2",certguidnotsafe,SAFETY_LEVEL1), runtime_error);
	BOOST_CHECK_THROW(CertBan("node3",certguidsafe,SAFETY_LEVEL1), runtime_error);
	// ban both certs level 1 (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,SAFETY_LEVEL1));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,SAFETY_LEVEL1));
	// should only show level 1 banned if safe search filter is not used
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "Off"), true);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "Off"), true);
	// should be able to certinfo on level 1 banned certs
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));
	
	// ban both certs level 2 (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,SAFETY_LEVEL2));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,SAFETY_LEVEL2));
	// no matter what filter won't show banned certs
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "Off"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "Off"), false);

	// shouldn't be able to certinfo on level 2 banned certs
	BOOST_CHECK_THROW(r = CallRPC("node1", "certinfo " + certguidsafe), runtime_error);
	BOOST_CHECK_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe), runtime_error);

	// unban both certs (only owner of SYS_CATEGORY can do this)
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidsafe,0));
	BOOST_CHECK_NO_THROW(CertBan("node1",certguidnotsafe,0));
	// safe to search regardless of filter
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "On"), true);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidsafe, "Off"), true);

	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "On"), false);
	BOOST_CHECK_EQUAL(CertFilter("node1", certguidnotsafe, "Off"), true);

	// should be able to certinfo on non banned certs
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidsafe));
	BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + certguidnotsafe));
	
}

BOOST_AUTO_TEST_CASE (generate_certpruning)
{
	UniValue r;
	// makes sure services expire in 100 blocks instead of 1 year of blocks for testing purposes
	#ifdef ENABLE_DEBUGRPC
		printf("Running generate_certpruning...\n");
		AliasNew("node1", "jagprune1", "changeddata1");
		// stop node2 create a service,  mine some blocks to expire the service, when we restart the node the service data won't be synced with node2
		StopNode("node2");
		BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certnew jagprune1 jag1 data 0"));
		const UniValue &arr = r.get_array();
		string guid = arr[1].get_str();
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		// we can find it as normal first
		BOOST_CHECK_EQUAL(CertFilter("node1", guid, "Off"), true);
		// then we let the service expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
		MilliSleep(2500);
		// make sure our offer alias doesn't expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate jagprune1 newdata privdata"));
		// then we let the service expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 50"));
		StartNode("node2");
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
		MilliSleep(2500);
		// now we shouldn't be able to search it
		BOOST_CHECK_EQUAL(CertFilter("node1", guid, "Off"), false);
		// and it should say its expired
		BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certinfo " + guid));
		BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

		// node2 shouldn't find the service at all (meaning node2 doesn't sync the data)
		BOOST_CHECK_THROW(CallRPC("node2", "certinfo " + guid), runtime_error);
		BOOST_CHECK_EQUAL(CertFilter("node2", guid, "Off"), false);

		// stop node3
		StopNode("node3");
		// make sure our offer alias doesn't expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate jagprune1 newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		// create a new service
		BOOST_CHECK_NO_THROW(r = CallRPC("node1", "certnew jagprune1 jag1 data 0"));
		const UniValue &arr1 = r.get_array();
		string guid1 = arr1[1].get_str();
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 70"));
		MilliSleep(2500);
		// stop and start node1
		StopNode("node1");
		StartNode("node1");
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		// give some time to propogate the new blocks across other 2 nodes
		MilliSleep(2500);
		// ensure you can still update before expiry
		BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + guid1 + " newdata privdata 0"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		MilliSleep(2500);
		// you can search it still on node1/node2
		BOOST_CHECK_EQUAL(CertFilter("node1", guid1, "Off"), true);
		BOOST_CHECK_EQUAL(CertFilter("node2", guid1, "Off"), true);
		// make sure our offer alias doesn't expire
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate jagprune1 newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 75"));
		MilliSleep(2500);
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasupdate jagprune1 newdata privdata"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		// ensure service is still active since its supposed to expire at 100 blocks of non updated services
		BOOST_CHECK_NO_THROW(CallRPC("node1", "certupdate " + guid1 + " newdata privdata 0"));
		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 5"));
		MilliSleep(2500);
		// you can search it still on node1/node2
		BOOST_CHECK_EQUAL(CertFilter("node1", guid1, "Off"), true);
		BOOST_CHECK_EQUAL(CertFilter("node2", guid1, "Off"), true);

		BOOST_CHECK_NO_THROW(CallRPC("node1", "generate 125"));
		MilliSleep(2500);
		// now it should be expired
		BOOST_CHECK_THROW(CallRPC("node2",  "certupdate " + guid1 + " newdata1 privdata1 0"), runtime_error);
		BOOST_CHECK_NO_THROW(CallRPC("node2", "generate 5"));
		MilliSleep(2500);
		BOOST_CHECK_EQUAL(CertFilter("node1", guid1, "Off"), false);
		BOOST_CHECK_EQUAL(CertFilter("node2", guid1, "Off"), false);
		// and it should say its expired
		BOOST_CHECK_NO_THROW(r = CallRPC("node2", "certinfo " + guid1));
		BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 1);	

		StartNode("node3");
		BOOST_CHECK_NO_THROW(CallRPC("node3", "generate 5"));
		MilliSleep(2500);
		// node3 shouldn't find the service at all (meaning node3 doesn't sync the data)
		BOOST_CHECK_THROW(CallRPC("node3", "certinfo " + guid1), runtime_error);
		BOOST_CHECK_EQUAL(CertFilter("node3", guid1, "Off"), false);
	#endif
}
BOOST_AUTO_TEST_SUITE_END ()