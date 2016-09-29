#include "test_syscoin_services.h"
#include "utiltime.h"
#include "util.h"
#include "amount.h"
#include "rpc/server.h"
#include "feedback.h"
#include <memory>
#include <string>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/thread.hpp>
#include <boost/lexical_cast.hpp>


// SYSCOIN testing setup
void StartNodes()
{
	printf("Stopping any test nodes that are running...\n");
	StopNodes();
	if(boost::filesystem::exists(boost::filesystem::system_complete("node1/regtest")))
		boost::filesystem::remove_all(boost::filesystem::system_complete("node1/regtest"));
	MilliSleep(1000);
	if(boost::filesystem::exists(boost::filesystem::system_complete("node2/regtest")))
		boost::filesystem::remove_all(boost::filesystem::system_complete("node2/regtest"));
	MilliSleep(1000);
	if(boost::filesystem::exists(boost::filesystem::system_complete("node3/regtest")))
		boost::filesystem::remove_all(boost::filesystem::system_complete("node3/regtest"));
	printf("Starting 3 nodes in a regtest setup...\n");
	StartNode("node1");
	StartNode("node2");
	StartNode("node3");

}
void StartMainNetNodes()
{
	StopMainNetNodes();
	printf("Starting 2 nodes in mainnet setup...\n");
	StartNode("mainnet1", false);
	StartNode("mainnet2", false);
}
void StopMainNetNodes()
{
	printf("Stopping mainnet1..\n");
	try{
		CallRPC("mainnet1", "stop");
	}
	catch(const runtime_error& error)
	{
	}	
	MilliSleep(3000);
	printf("Stopping mainnet2..\n");
	try{
		CallRPC("mainnet2", "stop");
	}
	catch(const runtime_error& error)
	{
	}	
	printf("Done!\n");
}
void StopNodes()
{
	printf("Stopping node1..\n");
	try{
		CallRPC("node1", "stop");
	}
	catch(const runtime_error& error)
	{
	}	
	MilliSleep(3000);
	printf("Stopping node2..\n");
	try{
		CallRPC("node2", "stop");
	}
	catch(const runtime_error& error)
	{
	}	
	MilliSleep(3000);
	printf("Stopping node3..\n");
	try{
		CallRPC("node3", "stop");
	}
	catch(const runtime_error& error)
	{
	}	
	MilliSleep(3000);
	printf("Done!\n");
}
void StartNode(const string &dataDir, bool regTest)
{
    boost::filesystem::path fpath = boost::filesystem::system_complete("../syscoind");
	string nodePath = fpath.string() + string(" -datadir=") + dataDir;
	if(regTest)
		nodePath += string(" -regtest -debug");
    boost::thread t(runCommand, nodePath);
	printf("Launching %s, waiting 3 seconds before trying to ping...\n", dataDir.c_str());
	MilliSleep(3000);
	while (1)
	{
		try{
			printf("Calling getinfo!\n");
			CallRPC(dataDir, "getinfo", regTest);
		}
		catch(const runtime_error& error)
		{
			printf("Waiting for %s to come online, trying again in 5 seconds...\n", dataDir.c_str());
			MilliSleep(5000);
			continue;
		}
		break;
	}
	printf("Done!\n");
}

void StopNode (const string &dataDir) {
	printf("Stopping %s..\n", dataDir.c_str());
	try{
		CallRPC(dataDir, "stop");
	}
	catch(const runtime_error& error)
	{
	}
	MilliSleep(3000);
}

UniValue CallRPC(const string &dataDir, const string& commandWithArgs, bool regTest)
{
	UniValue val;
	boost::filesystem::path fpath = boost::filesystem::system_complete("../syscoin-cli");
	string path = fpath.string() + string(" -datadir=") + dataDir;
	if(regTest)
		path += string(" -regtest ");
	else
		path += " ";
	path += commandWithArgs;
	string rawJson = CallExternal(path);
    val.read(rawJson);
	if(val.isNull())
		throw runtime_error("Could not parse rpc results");
	return val;
}
int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}
void safe_fclose(FILE* file)
{
      if (file)
         BOOST_VERIFY(0 == fclose(file));
	if(boost::filesystem::exists("cmdoutput.log"))
		boost::filesystem::remove("cmdoutput.log");
}
int runSysCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
	return nErr;
}
std::string CallExternal(std::string &cmd)
{
	cmd += " > cmdoutput.log || true";
	if(runSysCommand(cmd))
		return string("ERROR");
    boost::shared_ptr<FILE> pipe(fopen("cmdoutput.log", "r"), safe_fclose);
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
	if(fsize(pipe.get()) > 0)
	{
		while (!feof(pipe.get())) {
			if (fgets(buffer, 128, pipe.get()) != NULL)
				result += buffer;
		}
	}
    return result;
}
// generate n Blocks, with up to 10 seconds relay time buffer for other nodes to get the blocks.
// may fail if your network is slow or you try to generate too many blocks such that can't relay within 10 seconds
void GenerateBlocks(int nBlocks, const string& node)
{
  int height, newHeight, timeoutCounter;
  UniValue r;
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
  BOOST_CHECK_NO_THROW(r = CallRPC(node, "getinfo"));
  newHeight = find_value(r.get_obj(), "blocks").get_int() + nBlocks;
  const string &sBlocks = strprintf("%d",nBlocks);
  BOOST_CHECK_NO_THROW(r = CallRPC(node, "generate " + sBlocks));
  BOOST_CHECK_NO_THROW(r = CallRPC(node, "getinfo"));
  height = find_value(r.get_obj(), "blocks").get_int();
  BOOST_CHECK(height == newHeight);
  height = 0;
  timeoutCounter = 0;
  while(height != newHeight)
  {
	  MilliSleep(100);
	  BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "getinfo"));
	  height = find_value(r.get_obj(), "blocks").get_int();
	  timeoutCounter++;
	  if(timeoutCounter > 300)
		  break;
  }
  BOOST_CHECK(height == newHeight);
  height = 0;
  timeoutCounter = 0;
  while(height != newHeight)
  {
	  MilliSleep(100);
	  BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "getinfo"));
	  height = find_value(r.get_obj(), "blocks").get_int();
	  timeoutCounter++;
	  if(timeoutCounter > 300)
		  break;
  }
  BOOST_CHECK(height == newHeight);
  height = 0;
  timeoutCounter = 0;
}
void CreateSysRatesIfNotExist()
{
	string data = "{\\\"rates\\\":[{\\\"currency\\\":\\\"USD\\\",\\\"rate\\\":2690.1,\\\"precision\\\":2},{\\\"currency\\\":\\\"EUR\\\",\\\"rate\\\":2695.2,\\\"precision\\\":2},{\\\"currency\\\":\\\"GBP\\\",\\\"rate\\\":2697.3,\\\"precision\\\":2},{\\\"currency\\\":\\\"CAD\\\",\\\"rate\\\":2698.0,\\\"precision\\\":2},{\\\"currency\\\":\\\"BTC\\\",\\\"rate\\\":100000.0,\\\"precision\\\":8},{\\\"currency\\\":\\\"SYS\\\",\\\"rate\\\":1.0,\\\"precision\\\":2}]}";
	// should get runtime error if doesnt exist
	try{
		CallRPC("node1", "aliasupdate sysrates.peg " + data);
	}
	catch(const runtime_error& err)
	{
		GenerateBlocks(200, "node1");	
		GenerateBlocks(200, "node2");	
		GenerateBlocks(200, "node3");	
		BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew sysrates.peg " + data));
	}
	GenerateBlocks(5);
}
void CreateSysBanIfNotExist()
{
	string data = "{}";
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew sysban " + data));
	GenerateBlocks(5);
}
void CreateSysCategoryIfNotExist()
{
	string data = "\"{\\\"categories\\\":[{\\\"cat\\\":\\\"certificates\\\"},{\\\"cat\\\":\\\"wanted\\\"},{\\\"cat\\\":\\\"for sale > general\\\"},{\\\"cat\\\":\\\"for sale > wanted\\\"},{\\\"cat\\\":\\\"services\\\"}]}\"";
	
	BOOST_CHECK_NO_THROW(CallRPC("node1", "aliasnew syscategory " + data));
	GenerateBlocks(5);
}
void AliasBan(const string& node, const string& alias, int severity)
{
	string data = "{\\\"aliases\\\":[{\\\"id\\\":\\\"" + alias + "\\\",\\\"severity\\\":" + boost::lexical_cast<string>(severity) + "}]}";
	CallRPC(node, "aliasupdate sysban " + data);
	GenerateBlocks(5);
}
void OfferBan(const string& node, const string& offer, int severity)
{
	string data = "{\\\"offers\\\":[{\\\"id\\\":\\\"" + offer + "\\\",\\\"severity\\\":" + boost::lexical_cast<string>(severity) + "}]}";
	CallRPC(node, "aliasupdate sysban " + data);
	GenerateBlocks(5);
}
void CertBan(const string& node, const string& cert, int severity)
{
	string data = "{\\\"certs\\\":[{\\\"id\\\":\\\"" + cert + "\\\",\\\"severity\\\":" + boost::lexical_cast<string>(severity) + "}]}";
	CallRPC(node, "aliasupdate sysban " + data);
	GenerateBlocks(5);
}
string AliasNew(const string& node, const string& aliasname, const string& pubdata, string privdata, string safesearch)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasnew " + aliasname + " " + pubdata + " " + privdata + " " + safesearch));
	string pubkey;
	const UniValue &resultArray = r.get_array();
	pubkey = resultArray[1].get_str();
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "value").get_str(), pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() == privdata);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == true);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "value").get_str(), pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() != privdata);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == false);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "value").get_str(), pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() != privdata);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == false);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
	return pubkey;
}
void AliasTransfer(const string& node, const string& aliasname, const string& tonode, const string& pubdata, const string& privdata, string pubkey)
{
	UniValue r;
	if(pubkey.size() <= 0)
	{
		UniValue pkr = CallRPC(tonode, "generatepublickey");
		if (pkr.type() != UniValue::VARR)
			throw runtime_error("Could not parse rpc results");

		const UniValue &resultArray = pkr.get_array();
		pubkey = resultArray[0].get_str();		
	}
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasupdate " + aliasname + " " + pubdata + " " + privdata + " Yes " + pubkey));
	GenerateBlocks(10, tonode);
	GenerateBlocks(10, node);	
	// check its not mine anymore
	r = CallRPC(node, "aliasinfo " + aliasname);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == false);
	BOOST_CHECK(find_value(r.get_obj(), "value").get_str() == pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() != privdata);
	// check xferred right person and data changed
	r = CallRPC(tonode, "aliasinfo " + aliasname);
	BOOST_CHECK(find_value(r.get_obj(), "value").get_str() == pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() == privdata);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == true);
}
void AliasUpdate(const string& node, const string& aliasname, const string& pubdata, const string& privdata, string safesearch)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}

	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasupdate " + aliasname + " " + pubdata + " " + privdata + " " + safesearch));
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(CallRPC(node, "aliasupdate " + aliasname + " " + pubdata + " " + privdata + " " + safesearch), runtime_error);
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK(find_value(r.get_obj(), "value").get_str() == pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() == privdata);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == true);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK(find_value(r.get_obj(), "value").get_str() == pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == false);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() != privdata);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "aliasinfo " + aliasname));
	BOOST_CHECK(find_value(r.get_obj(), "name").get_str() == aliasname);
	BOOST_CHECK(find_value(r.get_obj(), "value").get_str() == pubdata);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_bool() == false);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK(find_value(r.get_obj(), "privatevalue").get_str() != privdata);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "expired").get_int(), 0);
}
bool AliasFilter(const string& node, const string& regex, const string& safesearch)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "aliasfilter " + regex + " /""/ " + safesearch));
	const UniValue &arr = r.get_array();
	return !arr.empty();
}
bool OfferFilter(const string& node, const string& regex, const string& safesearch)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerfilter " + regex + " /""/ " + safesearch));
	const UniValue &arr = r.get_array();
	return !arr.empty();
}
bool CertFilter(const string& node, const string& regex, const string& safesearch)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certfilter " + regex + " /""/ " + safesearch));
	const UniValue &arr = r.get_array();
	return !arr.empty();
}
bool EscrowFilter(const string& node, const string& regex)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowfilter " + regex));
	const UniValue &arr = r.get_array();
	return !arr.empty();
}
const string CertNew(const string& node, const string& alias, const string& title, const string& data, bool privateData, const string& safesearch)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	string privateFlag = privateData? "1":"0";
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certnew " + alias + " " + title + " " + data + " " + privateFlag + " " + safesearch));
	const UniValue &arr = r.get_array();
	string guid = arr[1].get_str();
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == alias);
	BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	if(privateData)
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "Yes");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() != data);
	}
	else
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "No");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	}

	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	if(privateData)
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "Yes");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() != data);
	}
	else
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "No");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	}
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	return guid;
}
void CertUpdate(const string& node, const string& guid, const string& alias, const string& title, const string& data, bool privateData, string safesearch)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	UniValue r;
	string privateFlag = privateData? "1":" 0";
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certupdate " + guid + " " + alias + " " + title + " " + data + " " + privateFlag + " " + safesearch));
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(CallRPC(node, "certupdate " + guid + " " + alias + " " + title + " " + data + " " + privateFlag + " " + safesearch), runtime_error);
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == alias);
	BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == alias);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	if(privateData)
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "Yes");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() != data);
	}
	else
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "No");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	}

	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "certinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "alias").get_str() == alias);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	if(privateData)
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "Yes");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() != data);
	}
	else
	{
		BOOST_CHECK(find_value(r.get_obj(), "private").get_str() == "No");
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	}
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
}
void CertTransfer(const string& node, const string& guid, const string& toalias)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certinfo " + guid));
	string data = find_value(r.get_obj(), "data").get_str();

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certtransfer " + guid + " " + toalias));
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(CallRPC(node, "certtransfer " + guid + " " + toalias), runtime_error);
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "certinfo " + guid));
	bool privateData = find_value(r.get_obj(), "private").get_str() == "Yes";
	if(privateData)
	{
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() != data);
	}
	else
	{
		BOOST_CHECK(find_value(r.get_obj(), "data").get_str() == data);
	}
	BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
}
const string MessageNew(const string& fromnode, const string& tonode, const string& title, const string& data, const string& fromalias, const string& toalias)
{
	string otherNode;
	if(fromnode != "node1" && tonode != "node1")
		otherNode = "node1";
	else if(fromnode != "node2" && tonode != "node2")
		otherNode = "node2";
	else if(fromnode != "node3" && tonode != "node3")
		otherNode = "node3";
	UniValue r;
	BOOST_CHECK_NO_THROW(r = CallRPC(fromnode, "messagenew " + title + " " + data + " " + fromalias + " " + toalias));
	const UniValue &arr = r.get_array();
	string guid = arr[1].get_str();
	GenerateBlocks(5, fromnode);
	BOOST_CHECK_NO_THROW(r = CallRPC(fromnode, "messageinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "GUID").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "message").get_str() == data);
	BOOST_CHECK(find_value(r.get_obj(), "subject").get_str() == title);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode, "messageinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "GUID").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "message").get_str() != data);
	BOOST_CHECK(find_value(r.get_obj(), "subject").get_str() == title);
	BOOST_CHECK_NO_THROW(r = CallRPC(tonode, "messageinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "GUID").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "message").get_str() == data);
	BOOST_CHECK(find_value(r.get_obj(), "subject").get_str() == title);
	return guid;
}
const string OfferLink(const string& node, const string& alias, const string& guid, const string& commission, const string& newdescription)
{
	UniValue r;
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + guid));
	const string &olddescription = find_value(r.get_obj(), "description").get_str();
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerlink " + alias + " " + guid + " " + commission + " " + newdescription));
	const UniValue &arr = r.get_array();
	string linkedguid = arr[1].get_str();
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + linkedguid));
	if(!newdescription.empty())
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == newdescription);
	else
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == olddescription);

	string exmode = "ON";
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == linkedguid);
	BOOST_CHECK(find_value(r.get_obj(), "offerlink_guid").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "offerlink").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "commission").get_str() == commission);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	// linked offers always exclusive resell mode, cant resell a resell offere
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "offerinfo " + linkedguid));
	if(!newdescription.empty())
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == newdescription);
	else
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == olddescription);
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == linkedguid);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "offerinfo " + linkedguid));
	if(!newdescription.empty())
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == newdescription);
	else
		BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == olddescription);
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == linkedguid);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	return linkedguid;
}
const string OfferNew(const string& node, const string& aliasname, const string& category, const string& title, const string& qty, const string& price, const string& description, const string& currency, const string& certguid, const bool exclusiveResell, const string& paymentoptions, const string& geolocation, const string& safesearch)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	CreateSysRatesIfNotExist();
	UniValue r;
	string exclusivereselltmp =  exclusiveResell? "1": "0";
	string offercreatestr = "offernew sysrates.peg " + aliasname + " " + category + " " + title + " " + qty + " " + price + " " + description + " " + currency  + " " + certguid + " " + exclusivereselltmp + " " + paymentoptions + " " + geolocation + " " + safesearch;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, offercreatestr));
	const UniValue &arr = r.get_array();
	string guid = arr[1].get_str();
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + guid));
	string exmode = "ON";
	if(!exclusiveResell)
		exmode = "OFF";
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == guid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "offerinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == guid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "offerinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == guid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	return guid;
}

void OfferUpdate(const string& node, const string& aliasname, const string& offerguid, const string& category, const string& title, const string& qty, const string& price, const string& description, const string& currency, const bool isPrivate, const string& certguid, const bool exclusiveResell, const string& geolocation, string safesearch, string commission, string paymentoptions) {

	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2") {
		otherNode1 = "node3";
		otherNode2 = "node1";
	} else if(node == "node3") {
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	
	CreateSysRatesIfNotExist();

	UniValue r;
	string exclusivereselltmp = exclusiveResell? "1": "0";
	string privatetmp = isPrivate ? "1" : "0";
	string offerupdatestr = "offerupdate sysrates.peg " + aliasname + " " + offerguid + " " + category + " " + title + " " + qty + " " + price + " " + description + " " + currency + " " + privatetmp + " " + certguid + " " + exclusivereselltmp + " " + geolocation + " " + safesearch + " " + commission + " " + paymentoptions;
	

	BOOST_CHECK_NO_THROW(r = CallRPC(node, offerupdatestr));
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(r = CallRPC(node, offerupdatestr), runtime_error);	
	GenerateBlocks(10, node);

	string exmode = "ON";
	if(!exclusiveResell)
		exmode = "OFF";
		
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offerguid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	if(currency != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "true");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "offerinfo " + offerguid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	if(currency != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
	
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "offerinfo " + offerguid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	if(certguid != "nocert")
		BOOST_CHECK(find_value(r.get_obj(), "cert").get_str() == certguid);
	BOOST_CHECK(find_value(r.get_obj(), "exclusive_resell").get_str() == exmode);
	BOOST_CHECK(find_value(r.get_obj(), "title").get_str() == title);
	BOOST_CHECK(find_value(r.get_obj(), "category").get_str() == category);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "description").get_str() == description);
	if(paymentoptions != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == atoi(paymentoptions.c_str()));
	else
		BOOST_CHECK(find_value(r.get_obj(), "paymentoptions").get_int() == 1);
	if(currency != "NONE")
		BOOST_CHECK(find_value(r.get_obj(), "currency").get_str() == currency);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "price").get_str(), price);
	BOOST_CHECK(find_value(r.get_obj(), "geolocation").get_str() == geolocation);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	BOOST_CHECK(find_value(r.get_obj(), "safesearch").get_str() == safesearch);
}

void OfferAcceptFeedback(const string& node, const string& offerguid, const string& acceptguid, const string& feedback, const string& rating, const char& user, const bool israting) {

	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2") {
		otherNode1 = "node3";
		otherNode2 = "node1";
	} else if(node == "node3") {
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	

	UniValue r;
	string offerfeedbackstr = "offeracceptfeedback " + offerguid + " " + acceptguid + " " + feedback + " " + rating;
	

	BOOST_CHECK_NO_THROW(r = CallRPC(node, offerfeedbackstr));
	const UniValue &arr = r.get_array();
	string acceptTxid = arr[0].get_str();
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(CallRPC(node, offerfeedbackstr), runtime_error);	

	GenerateBlocks(10, node);
	string ratingstr = (israting? rating: "0");
	r = FindOfferAcceptFeedback(node, offerguid, acceptguid, acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "txid").get_str() == acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "rating").get_int() == atoi(ratingstr.c_str()));
	BOOST_CHECK(find_value(r.get_obj(), "feedback").get_str() == feedback);
	BOOST_CHECK(find_value(r.get_obj(), "feedbackuser").get_int() == user);
	
	r = FindOfferAcceptFeedback(otherNode1, offerguid, acceptguid, acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "txid").get_str() == acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "rating").get_int() == atoi(ratingstr.c_str()));
	BOOST_CHECK(find_value(r.get_obj(), "feedback").get_str() == feedback);
	BOOST_CHECK(find_value(r.get_obj(), "feedbackuser").get_int() == user);
	
	r = FindOfferAcceptFeedback(otherNode2, offerguid, acceptguid, acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "txid").get_str() == acceptTxid);
	BOOST_CHECK(find_value(r.get_obj(), "rating").get_int() == atoi(ratingstr.c_str()));
	BOOST_CHECK(find_value(r.get_obj(), "feedback").get_str() == feedback);
	BOOST_CHECK(find_value(r.get_obj(), "feedbackuser").get_int() == user);
}
void EscrowFeedback(const string& node, const string& escrowguid, const string& feedbackprimary, const string& ratingprimary,  char userprimary, const string& feedbacksecondary, const string& ratingsecondary,  char usersecondary, const bool israting) {

	UniValue r;
	string escrowfeedbackstr = "escrowfeedback " + escrowguid + " " + feedbackprimary + " " + ratingprimary + " " + feedbacksecondary + " " + ratingsecondary;

	BOOST_CHECK_NO_THROW(r = CallRPC(node, escrowfeedbackstr));
	const UniValue &arr = r.get_array();
	string escrowTxid = arr[0].get_str();
	// ensure mempool blocks second tx until it confirms
	BOOST_CHECK_THROW(CallRPC(node, escrowfeedbackstr), runtime_error);	

	GenerateBlocks(10, node);
	string ratingprimarystr = (israting? ratingprimary: "0");
	string ratingsecondarystr = (israting? ratingsecondary: "0");
	int foundFeedback = 0;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + escrowguid));
	const UniValue& escrowObj = r.get_obj();
	const UniValue &arrayBuyerFeedbackObject = find_value(escrowObj, "buyer_feedback");
	const UniValue &arraySellerFeedbackObject  = find_value(escrowObj, "seller_feedback");
	const UniValue &arrayArbiterFeedbackObject  = find_value(escrowObj, "arbiter_feedback");
	if(arrayBuyerFeedbackObject.type() == UniValue::VARR)
	{
		const UniValue &arrayBuyerFeedbackValue = arrayBuyerFeedbackObject.get_array();
		for(int j=0;j<arrayBuyerFeedbackValue.size();j++)
		{
			const UniValue& arrayBuyerFeedback = arrayBuyerFeedbackValue[j].get_obj();
			const string &escrowFeedbackTxid = find_value(arrayBuyerFeedback, "txid").get_str();
			if(foundFeedback == 0 && escrowFeedbackTxid == escrowTxid && (userprimary == FEEDBACKBUYER || usersecondary == FEEDBACKBUYER))
			{
				BOOST_CHECK(find_value(arrayBuyerFeedback, "feedbackuser").get_int() != FEEDBACKBUYER);
				if(userprimary == FEEDBACKBUYER)
				{
					BOOST_CHECK_EQUAL(find_value(arrayBuyerFeedback, "feedback").get_str() , feedbackprimary);
					BOOST_CHECK_EQUAL(find_value(arrayBuyerFeedback, "rating").get_int(), atoi(ratingprimarystr.c_str()));
				}
				else
				{
					BOOST_CHECK_EQUAL(find_value(arrayBuyerFeedback, "feedback").get_str() , feedbacksecondary);
					BOOST_CHECK_EQUAL(find_value(arrayBuyerFeedback, "rating").get_int(), atoi(ratingsecondarystr.c_str()));
				}
				
				foundFeedback++;
				break;
			}
		}
	}
	if(arraySellerFeedbackObject.type() == UniValue::VARR)
	{
		const UniValue &arraySellerFeedbackValue = arraySellerFeedbackObject.get_array();
		for(int j=0;j<arraySellerFeedbackValue.size();j++)
		{
			const UniValue &arraySellerFeedback = arraySellerFeedbackValue[j].get_obj();
			const string &escrowFeedbackTxid = find_value(arraySellerFeedback, "txid").get_str();
			if(foundFeedback <= 1 && escrowFeedbackTxid == escrowTxid && (userprimary == FEEDBACKSELLER || usersecondary == FEEDBACKSELLER))
			{
				BOOST_CHECK(find_value(arraySellerFeedback, "feedbackuser").get_int() != FEEDBACKSELLER);
				if(userprimary == FEEDBACKSELLER)
				{
					BOOST_CHECK_EQUAL(find_value(arraySellerFeedback, "feedback").get_str(), feedbackprimary);
					BOOST_CHECK_EQUAL(find_value(arraySellerFeedback, "rating").get_int(), atoi(ratingprimarystr.c_str()));
				}
				else
				{
					BOOST_CHECK_EQUAL(find_value(arraySellerFeedback, "feedback").get_str(), feedbacksecondary);
					BOOST_CHECK_EQUAL(find_value(arraySellerFeedback, "rating").get_int(), atoi(ratingsecondarystr.c_str()));
				}
				
				foundFeedback++;
				break;
			}
		}
	}
	if(arrayArbiterFeedbackObject.type() == UniValue::VARR)
	{
		const UniValue &arrayArbiterFeedbackValue = arrayArbiterFeedbackObject.get_array();
		for(int j=0;j<arrayArbiterFeedbackValue.size();j++)
		{
			const UniValue &arrayArbiterFeedback = arrayArbiterFeedbackValue[j].get_obj();
			const string &escrowFeedbackTxid = find_value(arrayArbiterFeedback, "txid").get_str();
			if(foundFeedback <= 1 && escrowFeedbackTxid == escrowTxid && (userprimary == FEEDBACKARBITER || usersecondary == FEEDBACKARBITER))
			{
				BOOST_CHECK(find_value(arrayArbiterFeedback, "feedbackuser").get_int() != FEEDBACKARBITER);
				if(userprimary == FEEDBACKARBITER)
				{
					BOOST_CHECK_EQUAL(find_value(arrayArbiterFeedback, "feedback").get_str() , feedbackprimary);
					BOOST_CHECK_EQUAL(find_value(arrayArbiterFeedback, "rating").get_int(), atoi(ratingprimarystr.c_str()));
				}
				else
				{
					BOOST_CHECK_EQUAL(find_value(arrayArbiterFeedback, "feedback").get_str() , feedbacksecondary);
					BOOST_CHECK_EQUAL(find_value(arrayArbiterFeedback, "rating").get_int(), atoi(ratingsecondarystr.c_str()));
				}
				foundFeedback++;
				break;
			}
		}
	}
	BOOST_CHECK_EQUAL(foundFeedback, 2); 
}
// offeraccept <alias> <guid> [quantity] [message]
const string OfferAccept(const string& ownernode, const string& buyernode, const string& aliasname, const string& offerguid, const string& qty, const string& pay_message, const string& resellernode) {

	CreateSysRatesIfNotExist();

	UniValue r;
	
	BOOST_CHECK_NO_THROW(r = CallRPC(buyernode, "offerinfo " + offerguid));
	int nCurrentQty = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	
	string rootofferguid = find_value(r.get_obj(), "offerlink_guid").get_str();
	int nQtyToAccept = atoi(qty.c_str());
	CAmount nTotal = find_value(r.get_obj(), "sysprice").get_int64()*nQtyToAccept;
	string sTargetQty = boost::to_string(nCurrentQty - nQtyToAccept);

	string offeracceptstr = "offeraccept " + aliasname + " " + offerguid + " " + qty + " " + pay_message;

	BOOST_CHECK_NO_THROW(r = CallRPC(buyernode, offeracceptstr));
	const UniValue &arr = r.get_array();
	string acceptguid = arr[1].get_str();

	GenerateBlocks(5, ownernode);
	GenerateBlocks(5, buyernode);
	
	const UniValue &acceptSellerValue = FindOfferAccept(ownernode, offerguid, acceptguid);
	CAmount nSellerTotal = find_value(acceptSellerValue, "systotal").get_int64();
	int discount = atoi(find_value(acceptSellerValue, "offer_discount_percentage").get_str().c_str());
	int lMarkup = 100 - discount;
	nTotal = (nTotal*lMarkup) / 100;

	BOOST_CHECK(find_value(acceptSellerValue, "pay_message").get_str() == pay_message);
	
	
	BOOST_CHECK_NO_THROW(r = CallRPC(buyernode, "offerinfo " + offerguid));
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	BOOST_CHECK_EQUAL(find_value(r.get_obj(), "quantity").get_str(),sTargetQty);
	BOOST_CHECK(find_value(r.get_obj(), "ismine").get_str() == "false");
	if(!rootofferguid.empty() && !resellernode.empty())
	{
		BOOST_CHECK_NO_THROW(r = CallRPC(resellernode, "offerinfo " + rootofferguid));
		nSellerTotal = find_value(r.get_obj(), "sysprice").get_int64()*nQtyToAccept;
		// now get the accept from the resellernode
		const UniValue &acceptReSellerValue = FindOfferAcceptList(resellernode, offerguid, acceptguid);
		CAmount nCommission = find_value(acceptReSellerValue, "systotal").get_int64();
		nSellerTotal += nCommission;
		BOOST_CHECK(find_value(acceptReSellerValue, "pay_message").get_str() != pay_message);
		GenerateBlocks(5, "node1");
		GenerateBlocks(5, "node2");
		GenerateBlocks(5, "node3");

		BOOST_CHECK(find_value(acceptSellerValue, "ismine").get_str() == "true");
		BOOST_CHECK(find_value(acceptReSellerValue, "ismine").get_str() == "true");
	}
	BOOST_CHECK_EQUAL(nSellerTotal, nTotal);
	return acceptguid;
}
const string EscrowNew(const string& node, const string& buyeralias, const string& offerguid, const string& qty, const string& message, const string& arbiteralias, const string& selleralias)
{
	string otherNode1 = "node2";
	string otherNode2 = "node3";
	if(node == "node2")
	{
		otherNode1 = "node3";
		otherNode2 = "node1";
	}
	else if(node == "node3")
	{
		otherNode1 = "node1";
		otherNode2 = "node2";
	}
	UniValue r;
	int nQty = atoi(qty.c_str());
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offerguid));
	int nQtyBefore = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrownew " + buyeralias + " " + offerguid + " " + qty + " " + message + " " + arbiteralias));
	const UniValue &arr = r.get_array();
	string guid = arr[1].get_str();
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offerguid));
	CAmount offerprice = find_value(r.get_obj(), "sysprice").get_int64();
	int nQtyAfter = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	// escrow should deduct qty
	BOOST_CHECK_EQUAL(nQtyAfter, nQtyBefore-nQty);
	CAmount nTotal = offerprice*nQty;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "escrow").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "systotal").get_int64() == nTotal);
	BOOST_CHECK(find_value(r.get_obj(), "arbiter").get_str() == arbiteralias);
	BOOST_CHECK(find_value(r.get_obj(), "seller").get_str() == selleralias);
	BOOST_CHECK(find_value(r.get_obj(), "pay_message").get_str() != message);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode1, "escrowinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "escrow").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "systotal").get_int64() == nTotal);
	BOOST_CHECK(find_value(r.get_obj(), "arbiter").get_str() == arbiteralias);
	BOOST_CHECK(find_value(r.get_obj(), "seller").get_str() == selleralias);
	BOOST_CHECK_NO_THROW(r = CallRPC(otherNode2, "escrowinfo " + guid));
	BOOST_CHECK(find_value(r.get_obj(), "escrow").get_str() == guid);
	BOOST_CHECK(find_value(r.get_obj(), "offer").get_str() == offerguid);
	BOOST_CHECK(find_value(r.get_obj(), "quantity").get_str() == qty);
	BOOST_CHECK(find_value(r.get_obj(), "systotal").get_int64() == nTotal);
	BOOST_CHECK(find_value(r.get_obj(), "arbiter").get_str() == arbiteralias);
	BOOST_CHECK(find_value(r.get_obj(), "seller").get_str() == selleralias);
	return guid;
}
void EscrowRelease(const string& node, const string& guid)
{
	UniValue r;

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + guid));
	string offer = find_value(r.get_obj(), "offer").get_str();

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferBefore = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());

	BOOST_CHECK_NO_THROW(CallRPC(node, "escrowrelease " + guid));
	GenerateBlocks(10, node);

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferAfter = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	// release doesn't alter qty
	BOOST_CHECK_EQUAL(nQtyOfferBefore, nQtyOfferAfter);

}
void EscrowRefund(const string& node, const string& guid)
{
	UniValue r;

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + guid));
	int nQtyEscrow = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	string offer = find_value(r.get_obj(), "offer").get_str();

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferBefore = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());

	BOOST_CHECK_NO_THROW(CallRPC(node, "escrowrefund " + guid));
	GenerateBlocks(10, node);

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferAfter = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	// refund adds qty
	BOOST_CHECK_EQUAL(nQtyOfferAfter, nQtyOfferBefore+nQtyEscrow);
}
void EscrowClaimRefund(const string& node, const string& guid)
{
	UniValue r;

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + guid));
	string offer = find_value(r.get_obj(), "offer").get_str();

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferBefore = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());

	BOOST_CHECK_NO_THROW(CallRPC(node, "escrowrefund " + guid));
	GenerateBlocks(10, node);

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferAfter = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	// claim doesn't touch qty
	BOOST_CHECK_EQUAL(nQtyOfferAfter, nQtyOfferBefore);
}
void OfferAddWhitelist(const string& node,const string& offerguid, const string& aliasname, const string& discount)
{
	bool found = false;
	UniValue r;
	BOOST_CHECK_NO_THROW(CallRPC(node, "offeraddwhitelist " + offerguid + " " + aliasname + " " + discount));
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerwhitelist " + offerguid));
	const UniValue &arrayValue = r.get_array();
	for(int i=0;i<arrayValue.size();i++)
	{
		const string &aliasguid = find_value(arrayValue[i].get_obj(), "alias").get_str();
		
		if(aliasguid == aliasname)
		{
			const string& discountpct = discount + "%";
			found = true;
			BOOST_CHECK_EQUAL(find_value(arrayValue[i].get_obj(), "offer_discount_percentage").get_str(), discountpct);
		}

	}
	BOOST_CHECK(found);
}
void OfferRemoveWhitelist(const string& node, const string& offer, const string& aliasname)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(CallRPC(node, "offerremovewhitelist " + offer + " " + aliasname));
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerwhitelist " + offer));
	const UniValue &arrayValue = r.get_array();
	for(int i=0;i<arrayValue.size();i++)
	{
		const string &aliasguid = find_value(arrayValue[i].get_obj(), "alias").get_str();
		BOOST_CHECK(aliasguid != aliasname);
	}
}
void OfferClearWhitelist(const string& node, const string& offer)
{
	UniValue r;
	BOOST_CHECK_NO_THROW(CallRPC(node, "offerclearwhitelist " + offer));
	GenerateBlocks(10, node);
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerwhitelist " + offer));
	const UniValue &arrayValue = r.get_array();
	BOOST_CHECK(arrayValue.empty());

}
const UniValue FindOfferAccept(const string& node, const string& offerguid, const string& acceptguid, bool nocheck)
{
	UniValue r, ret;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offeracceptinfo " + offerguid));
	BOOST_CHECK(r.type() == UniValue::VARR);
	const UniValue &arrayValue = r.get_array();
	for(int i=0;i<arrayValue.size();i++)
	{		
		const UniValue& acceptObj = arrayValue[i].get_obj();
		const string &acceptvalueguid = find_value(acceptObj, "id").get_str();
		const string &offervalueguid = find_value(acceptObj, "offer").get_str();
		if(acceptvalueguid == acceptguid && offervalueguid == offerguid)
		{
			ret = acceptObj;
			break;
		}

	}
	if(!nocheck)
		BOOST_CHECK(!ret.isNull());
	return ret;
}
const UniValue FindOfferAcceptList(const string& node, const string& offerguid, const string& acceptguid, bool nocheck)
{
	UniValue r, ret;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offeracceptlist " + acceptguid));
	BOOST_CHECK(r.type() == UniValue::VARR);
	const UniValue &arrayValue = r.get_array();
	for(int i=0;i<arrayValue.size();i++)
	{		
		const UniValue& acceptObj = arrayValue[i].get_obj();
		const string &acceptvalueguid = find_value(acceptObj, "id").get_str();
		const string &offervalueguid = find_value(acceptObj, "offer").get_str();
		if(acceptvalueguid == acceptguid && offervalueguid == offerguid)
		{
			ret = acceptObj;
			break;
		}

	}
	if(!nocheck)
		BOOST_CHECK(!ret.isNull());
	return ret;
}
const UniValue FindOfferAcceptFeedback(const string& node, const string& offerguid, const string& acceptguid,const string& accepttxid, bool nocheck)
{
	UniValue r, ret;
	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offeracceptinfo " + offerguid));
	BOOST_CHECK(r.type() == UniValue::VARR);
	const UniValue &arrayValue = r.get_array();
	for(int i=0;i<arrayValue.size();i++)
	{
		const UniValue& acceptObj = arrayValue[i].get_obj();
		const string &acceptvalueguid = find_value(acceptObj, "id").get_str();
		const string &offervalueguid = find_value(acceptObj, "offer").get_str();
		
		if(acceptvalueguid == acceptguid && offervalueguid == offerguid)
		{
			const UniValue &arrayBuyerFeedbackObject = find_value(acceptObj, "buyer_feedback");
			const UniValue &arraySellerFeedbackObject  = find_value(acceptObj, "seller_feedback");
			if(arrayBuyerFeedbackObject.type() == UniValue::VARR)
			{
				const UniValue &arrayBuyerFeedbackValue = arrayBuyerFeedbackObject.get_array();
				for(int j=0;j<arrayBuyerFeedbackValue.size();j++)
				{
					const UniValue& arrayBuyerFeedback = arrayBuyerFeedbackValue[j].get_obj();
					const string &acceptFeedbackTxid = find_value(arrayBuyerFeedback, "txid").get_str();
					if(acceptFeedbackTxid == accepttxid)
					{
						ret = arrayBuyerFeedback;
						return ret;
					}
				}
			}
			if(arraySellerFeedbackObject.type() == UniValue::VARR)
			{
				const UniValue &arraySellerFeedbackValue = arraySellerFeedbackObject.get_array();
				for(int j=0;j<arraySellerFeedbackValue.size();j++)
				{
					const UniValue &arraySellerFeedback = arraySellerFeedbackValue[j].get_obj();
					const string &acceptFeedbackTxid = find_value(arraySellerFeedback, "txid").get_str();
					if(acceptFeedbackTxid == accepttxid)
					{
						ret = arraySellerFeedback;
						return ret;
					}
				}
			}
			break;
		}

	}
	if(!nocheck)
		BOOST_CHECK(!ret.isNull());
	return ret;
}
// not that this is for escrow dealing with non-linked offers
void EscrowClaimRelease(const string& node, const string& guid)
{
	UniValue r;

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "escrowinfo " + guid));
	string offer = find_value(r.get_obj(), "offer").get_str();

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferBefore = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());

	BOOST_CHECK_NO_THROW(CallRPC(node, "escrowrelease " + guid));
	GenerateBlocks(10, node);

	BOOST_CHECK_NO_THROW(r = CallRPC(node, "offerinfo " + offer));
	int nQtyOfferAfter = atoi(find_value(r.get_obj(), "quantity").get_str().c_str());
	// release doesn't alter qty
	BOOST_CHECK_EQUAL(nQtyOfferBefore, nQtyOfferAfter);
	
}
BasicSyscoinTestingSetup::BasicSyscoinTestingSetup()
{
}
BasicSyscoinTestingSetup::~BasicSyscoinTestingSetup()
{
}
SyscoinTestingSetup::SyscoinTestingSetup()
{
	StartNodes();
}
SyscoinTestingSetup::~SyscoinTestingSetup()
{
	StopNodes();
}
SyscoinMainNetSetup::SyscoinMainNetSetup()
{
	StartMainNetNodes();
}
SyscoinMainNetSetup::~SyscoinMainNetSetup()
{
	StopMainNetNodes();
}
