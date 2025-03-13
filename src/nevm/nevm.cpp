// Copyright (c) 2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <nevm/nevm.h>
#include <nevm/sha3.h>
#include <util/strencodings.h>
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

