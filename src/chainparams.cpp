// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
    0x12345678
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xa5;
        pchMessageStart[1] = 0xdc;
        pchMessageStart[2] = 0x73;
        pchMessageStart[3] = 0x01;
        vAlertPubKey = ParseHex("0430315603cbb1b5285e6c1afd36a148e6826c8d805297987928734326817da7eada08fcf2082e9f90527f2f0d9d18d43141e9316eb30ed26c13df9c64dff5841d");
        nDefaultPort = 11984;
        nRPCPort = 11985;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);
        nSubsidyHalvingInterval = 700800; // 2 years
        nMasternodePortForkHeight = 1246400 - 1000; // ~end sep 2017
        nRewardForkHeight1 = 1246400; // ~end sep 2017
        nRewardForkHeight2 = 1275200; // ~end oct 2017

        // Genesis block
        const char* pszTimestamp = "18-01-14 - Anti-fracking campaigners chain themselves to petrol pumps";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 16 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0443ba25ce09007eb0958785d9266cfca19c3348beed8819d1ec76e9916fe1579e13ec4bf8daf0860825f509c20e485417e5603f397685571e51c17d53a16e5ce3") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1521220942;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 1362818;


        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x00000c2156e777861caaffc8739b39c8922d554f5fe957a558efdfa3e195149e"));
        assert(genesis.hashMerkleRoot == uint256("0x8e9f0276156f83b92a732492f4b531b30e973ce078d178f9c217ead050f5365c"));

        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,28);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,4);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,28 + 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0xFE, 0x52, 0xF8};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0xFE, 0x52, 0xCC};

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf4;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0x13;
        pchMessageStart[3] = 0x0c;

        vAlertPubKey = ParseHex("04703fdfdeb8af591b7de4370d0c44a63020a33ab7f57462a6b00b4c5fda63b35a758c9ab33ee35fbafb0cf11822081522b22e8076402cb7253a7c3b26c0ece9fd");

        nDefaultPort = 21974;
        nRPCPort = 21975;
        strDataDir = "testnet3";

        nMasternodePortForkHeight = 400;
        nRewardForkHeight1 = 500;
        nRewardForkHeight2 = 1000;

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1521220943;
        genesis.nNonce = 896868;


        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000a3396cfb5858b0933fb453d8e2ed403e65551c6f8fe3ede0b222d6a4086"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,80);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,44);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,88 + 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x3a, 0x80, 0x61, 0xa0};
        base58Prefixes[EXT_SECRET_KEY] = {0x3a, 0x80, 0x58, 0x37};
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1c;
        pchMessageStart[2] = 0xc6;
        pchMessageStart[3] = 0x51;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1521220943;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 3;
        nDefaultPort = 18454;
        strDataDir = "regtest";

        hashGenesisBlock = genesis.GetHash();
        // assert(hashGenesisBlock == uint256("0x000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
