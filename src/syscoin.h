#ifndef  SYSCOIN_H
#define SYSCOIN_H

std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const json_spirit::Value& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const json_spirit::Value& value);

static const int SYSCOIN_TX_VERSION = 0x7400;
static const int64 MIN_AMOUNT = COIN;
static const unsigned int MAX_NAME_LENGTH = 255;
static const unsigned int MAX_VALUE_LENGTH = 1023;
static const unsigned int MIN_ACTIVATE_DEPTH = 120;
static const unsigned int MIN_ACTIVATE_DEPTH_CAKENET = 1;


#endif // SYSCOIN_H
