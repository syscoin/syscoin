// Copyright (c) 2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <uint256.h>
#include <arith_uint256.h>
#include <nevm/nevm.h>
#include <nevm/sha3.h>
#include <logging.h>
#include <util/strencodings.h>
#include <key_io.h>
#include <math.h>
const arith_uint256 nMax = arith_uint256(MAX_MONEY);
int nibblesToTraverse(const std::string &encodedPartialPath, const std::string &path, int pathPtr) {
  std::string partialPath;
  // typecast as the character
  uint8_t partialPathInt; 
  char pathPtrInt[2] = {encodedPartialPath[0], '\0'};
  if(!ParseUInt8(pathPtrInt, &partialPathInt))
    return -1;
  if(partialPathInt == 0 || partialPathInt == 2){
    partialPath = encodedPartialPath.substr(2);
  }else{
    partialPath = encodedPartialPath.substr(1);
  }
  if(partialPath == path.substr(pathPtr, partialPath.size())){
    return partialPath.size();
  }else{
    return -1;
  }
}
std::string hexToASCII(std::string hex) 
{ 
    // initialize the ASCII code string as empty. 
    std::string ascii;
    uint8_t ch;
    for (size_t i = 0; i < hex.length(); i += 2) 
    { 
        // extract two characters from hex string 
        std::string part = hex.substr(i, 2); 
  
        // change it into base 16 and  
        // typecast as the character 
        if(!ParseUInt8FromHex(part, &ch))
          return ascii;
  
        // add this char to final ASCII string 
        ascii += ch; 
    } 
    return ascii; 
} 
bool VerifyProof(dev::bytesConstRef path, const dev::RLP& value, const dev::RLP& parentNodes, const dev::RLP& root) {
  
  dev::RLP currentNode;
  const int len = parentNodes.itemCount();
  dev::RLP nodeKey = root;       
  int pathPtr = 0;

  const std::string &pathString = dev::toHex(path);
  int nibbles;
  char pathPtrInt[2];
  uint8_t pathInt;
  for (int i = 0 ; i < len ; i++) {
    currentNode = parentNodes[i];
    if(!nodeKey.payload().contentsEqual(sha3(currentNode.data()).ref().toVector())){
      return false;
    } 

    if(pathPtr > (int)pathString.size()){
      return false;
    }
    switch(currentNode.itemCount()){
      case 17://branch node
        if(pathPtr == (int)pathString.size()){
          if(currentNode[16].payload().contentsEqual(value.data().toVector())){
            return true;
          }else{
            return false;
          }
        }
        pathPtrInt[0] = pathString[pathPtr];
        pathPtrInt[1] = '\0';
        if(!ParseUInt8FromHex(pathPtrInt, &pathInt)) {
          return false;
        }
        nodeKey = currentNode[pathInt]; //must == sha3(rlp.encode(currentNode[path[pathptr]]))
        pathPtr += 1;
        break;
      case 2:
        nibbles = nibblesToTraverse(toHex(currentNode[0].payload()), pathString, pathPtr);
        if(nibbles <= -1) {
          return false;
        }
        pathPtr += nibbles;
        if(pathPtr == (int)pathString.size()) { //leaf node
          dev::bytes nodeVec(currentNode[1].toBytes());
          // https://eips.ethereum.org/EIPS/eip-2718 first byte less than 0x7f is the transaction type and not part of RLP
          if(nodeVec[0] < 0x7f) {
            nodeVec = dev::bytes(nodeVec.begin()+1, nodeVec.end());
          }
          if(nodeVec == value.data().toBytes()){
            return true;
          } else {
            return false;
          }
        } else {//extension node
          nodeKey = currentNode[1];
        }
        break;
      default:
        return false;
    }
  }
  
  return false;
}
/**
 * @brief Parse call data for freezeBurn(uint value, address assetAddr, uint256 tokenId, string memory syscoinAddr)
 *
 * @param vchInputExpectedMethodHash The 4-byte Keccak selector for freezeBurn(...)
 * @param vchInputData     The raw call data (including the 4-byte method ID)
 * @param outputAmount     [out] The bridging amount, scaled to local precision
 * @param witnessAddress   [out] The user’s Syscoin address extracted from the string param
 *
 * @return true if parsing succeeds, false otherwise
 */
bool parseNEVMMethodInputData(
    const std::vector<unsigned char>& vchInputExpectedMethodHash,
    const std::vector<unsigned char>& vchInputData,
    CAmount &outputAmount,
    std::string &witnessAddress
) {
    // Minimal length check:
    //   4 bytes for selector + 4 * 32 = 132 bytes of "static" data,
    //   plus 32 bytes for string length, plus at least 9 for a minimal bech32...
    //   So let's pick 4+128+32+9 = 173 as a minimal example check
    if (vchInputData.size() < 173) {
        return false;
    }

    // 1) Extract method hash
    std::vector<unsigned char> vchMethodHash(
        vchInputData.begin(),
        vchInputData.begin() + 4
    );
    if (vchMethodHash != vchInputExpectedMethodHash) {
        // Not the freezeBurn function
        return false;
    }

    // 2) Parse param1: `value` (offset [4..36])
    std::vector<unsigned char> vchValue(
        vchInputData.begin() + 4,
        vchInputData.begin() + 36
    );
    // Ethereum is big-endian, we reverse to interpret as little-endian 64
    std::reverse(vchValue.begin(), vchValue.end());
    arith_uint256 bigValue = UintToArith256(uint256(vchValue));
    if(bigValue > nMax) {
      return false;
    }
    outputAmount = static_cast<CAmount>(bigValue.GetLow64());
    // 3) Parse param2: `assetAddr` (offset [36..68])
    //    The actual address is the **last 20 bytes** of that 32-byte word. Skip this one.

    // 4) Parse param3: `tokenId` (offset [68..100]). Skip this one.
 
    // 5) Parse param4: `syscoinAddr` => We get a 32-byte offset pointer at [100..132].
    //    We'll read that offset, then read the string length, then the string data.
    std::vector<unsigned char> vchOffsetVal(
        vchInputData.begin() + 100,
        vchInputData.begin() + 132
    );
    std::reverse(vchOffsetVal.begin(), vchOffsetVal.end());
    arith_uint256 offsetArith = UintToArith256(uint256(vchOffsetVal));
    uint64_t offsetToString = offsetArith.GetLow64();
    // offset is relative to the *start of the method params* (excluding the 4-byte selector),
    // i.e. 0 means param1 starts at offset 0, param2 at offset 32, etc.

    // Safety checks
    // The dynamic area starts at offsetToString, which must be >= 128 bytes (since the first 4 params are 128).
    if (offsetToString < 128 || offsetToString >= vchInputData.size()) {
        return false;
    }
    // Then first 32 bytes there is the length of the string
    size_t strLenOffset = 4 + offsetToString; // 4 bytes for method selector
    if (strLenOffset + 32 > vchInputData.size()) {
        return false;
    }
    std::vector<unsigned char> vchStrLen(
        vchInputData.begin() + strLenOffset,
        vchInputData.begin() + strLenOffset + 32
    );
    std::reverse(vchStrLen.begin(), vchStrLen.end());
    arith_uint256 strLenArith = UintToArith256(uint256(vchStrLen));
    uint64_t lenString = strLenArith.GetLow64();

    // Now read the actual string
    size_t strDataPos = strLenOffset + 32;
    if (strDataPos + lenString > vchInputData.size()) {
        return false;
    }
    std::vector<unsigned char> vchString(
        vchInputData.begin() + strDataPos,
        vchInputData.begin() + strDataPos + lenString
    );

    // Convert to ASCII
    witnessAddress = std::string(vchString.begin(), vchString.end());

    return true;
}

