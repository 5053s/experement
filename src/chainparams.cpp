// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>
#include <memory>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.nTime = nTimeTx;

    CBlock genesis;
    genesis.nTime    = nTimeBlock;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTimeTx, uint32_t nTimeBlock, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Fighting flares on outskirts of Tripoli";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTimeTx, nTimeBlock, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP16Height = 1;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("3563d19f66aa85f33d1898f51bd4d38708e776cdae1a18e0cad8332d03b9f067");
        consensus.powLimit =            uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 32;
        consensus.bnInitialHashTarget = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 40;

        consensus.nTargetTimespan = 1 * 24 * 60 * 60; // 1 day
        consensus.nStakeTargetSpacing = 30; // 30-second block spacing
        consensus.nTargetSpacingWorkMax = 12 * consensus.nStakeTargetSpacing; // 2-hour
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing;
        consensus.nStakeMinAge = 60 * 60 * 24 * 30; // minimum age for coin age
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nModifierInterval = 6 * 60 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 100;

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000002f1242c3c5f261b2"); // to block 2368300

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x79c6f56bff70c17a2ea17b926f0abb3af1f017348ab796cd29be7fb00327bf1d"); //2368300

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xd0;
        vAlertPubKey = ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
        nDefaultPort = 3333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1554579000, 133964, 0x1e0ffff0, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x37d4696c5072cd012f3b7c651e5ce56a1383577e4edacc2d289ec9b25eebfd5e"));
        assert(genesis.hashMerkleRoot == uint256S("0xb82fb0f59328af96928f3a7648461f3db41fbfc2fef4e5ec6f7cf78ca067eacc"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("dnsseed.sumcoinpool.org");
	    vSeeds.emplace_back("dnsseed.minesum.com");
        vSeeds.emplace_back("dnsseed.sumcoinwallet.org");
	    vSeeds.emplace_back("dnsseed.sumnode.io");
	    vSeeds.emplace_back("dnsseed.sumcoinmining.org");
	    vSeeds.emplace_back("sumdnsseed.moonypool.com");
	    vSeeds.emplace_back("dnsseed.sumcoin.space");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); //  hexid = "3F"
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);  //
        //base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,200); //
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191);  //  hexid = "BF"
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB4, 0x1C};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAB, 0xE6};

        // human readable prefix to bench32 address
        bech32_hrp = "sum";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {  0,    uint256S("0x37d4696c5072cd012f3b7c651e5ce56a1383577e4edacc2d289ec9b25eebfd5e")},
                { 2880,  uint256S("0x31dfe91b64cbbb167b4e4c644ad7b008bb4bb8ca4e42aea02f938f445dc37cff")},
                { 5760,  uint256S("0x87de6e561bb0ab66095b272450cabbb0b11fb272e5ae37123ba1464a5de74f5c")},
                { 8640,  uint256S("0x19c100388b8a8bc0230f43c4355733e2b3375e08f1667449678ec14f66174aae")},
                {11520,  uint256S("0x0fcc3eacab1e532325f1c5bde0372b78e999a504a8eaaf3d4628038de6735d30")},
                {14400,  uint256S("0x6b55672438b707c59c95e7681a9914c4d201d2cdf5f42d902d53ed23042e028a")},
                {28800,  uint256S("0x8c7fdd9dd713a964e09339593ca82a738135d6cd82421198311d7a3931742e04")},
                {57600,  uint256S("0xedbe7a9e2e20c8c12fea25dc9be9268bfa308145fa68d2d2ce54dc405cf12e76")},
                {115200, uint256S("0xe386f62c30a46f6b565ffc8a3fdf73e5e76e9f2f400d5cba1911e7732b52bd8d")},
                {172800, uint256S("0x341f603628dbe328512d9507066241d9fcc4c81ac91dd9bc87e2184ed5787b80")},
                {201600, uint256S("0x6bbde0a86b6e1efa71333bb3636f02931ebb872157b48c674efde25054a571b3")},
                {216000, uint256S("0x7f1d6d0c386cc6a6d5eb85877adb039d7747c6047d84e311b7213bf237c78b7c")},
                {230400, uint256S("0x8857a4bd70e6aee0eec8902cd88ed378c3d73d625a3920c67d393c83176d12af")},
                {259200, uint256S("0x886fbe4eebd29e5aba9c3cb1d2319aaba6053d6e6956d7af79f99da19641895e")},
                {285120, uint256S("0x1b33c03b4a819112be0828d0cedcb2cb01c490ce224b9197ebb622bb13e26680")},
                {313920, uint256S("0x137bfb551a6d4e9136d241e1a2391ac310acc0475b0afa2c51cabda16cc1e055")},
                {342720, uint256S("0x5f4d51dba279f2cb7ae0d7ec85a4f204d3577510fc01ba2c2cf2032315d8a296")},
                {371520, uint256S("0x47eb97737152c9e3382336f27f700d950a98c705224a768aba806c2296d89b79")},
                {400320, uint256S("0x70de8d2e57f15f5e0b2e9abf603de8c788b0c7a77fe56011c78f582bfb0f131d")},
                {429120, uint256S("0x8811d063cd09444e831270d6f7dc72ce348774b216790da34c8c8ba33412f563")},
                {443520, uint256S("0xb17262650aeaf2eb01cab804e17f736f0942ac7a4a3f71461d7adeea5e34e768")},
                {452160, uint256S("0x51c53d431e8ebf232842fe37c81bf2fb4d40b171065a23cea9824d818e643ba5")},
                {457920, uint256S("0x717050f4a4a96f2d7b4c13fe2db70dc2998c31fea01607d9529b8dfeb434bc56")},
		        {472320, uint256S("0x3dccd8aaef590f102c7e3cd8200eb666a68d0356a24c87b51617314adb73e24c")},
		        {501120, uint256S("0xb0f6796740602fa097685f4d572090e956b33154914bd20ef2bedbf01a706d31")},
		        {527040, uint256S("0x1b3eb4800f56305d50c86c373131faafead605efeb6bf61c5df4044a1aec4d7f")},
		        {529920, uint256S("0xbe82c887af163c8c3a117497cfa909113067e25a8258b6644684c28d28ff1fdd")},
		        {544320, uint256S("0x3687c221709bd7c1c0848097df91cf6b1ff413e352e4f65e1ced6f4c94e07ec7")},
		        {558720, uint256S("0x25ed1e5a99938e5fd2503c4be4a435d7d582387f0d07587f5fccf03f7244282a")},
		        {573120, uint256S("0x7eefb09f6c5ad6874352b4c089d0dd8e9cf34b4d2537bcbef6bd0ea70a065998")},
		        {587520, uint256S("0x5952411159da3f15c29795673730166b1adb6d66e4abe681c1b6ea994589cb6b")},
		        {601920, uint256S("0x794df734a9ddcf3b7d460de7fde59e2ef83e9311e19800662344c46b2cec66e5")},
		        {616320, uint256S("0x2df1470ec7f86b972ca0d2d64de1306813e1e882e2e9f5cb4906a175311ef168")},
		        {630720, uint256S("0xa1b2fc648d66e8cd93869e99264ba892420370c98c2c0850e64d4a88415f92f1")},
		        {645120, uint256S("0x4ce5317488df663f0430caee55c602d2a29170812690b818f91a9c64fb4bfaac")},
		        {659520, uint256S("0x03c1bd4a9458439c9f258875273253ded816070e06a0f6331f61bf8b8f41fd74")},
		        {673920, uint256S("0x13ce1beec7b38cf76d3df4b6979a30cf69b4b0b0e34d481e28d427c9b09b5375")},
		        {688320, uint256S("0x4dd168a040c72b40d35bda63273dd2127f3e2ac84f8aadbed415fc19be3fbc85")},
		        {702720, uint256S("0xb5ac308d7c89dafa60abbb95b715945dd9b9672176dd280939ce75804e266a20")},
		        {717120, uint256S("0x42c18d5a929ea22e18843c8922e9bf0951728b831cee1ac9712b9abd1e04d785")},
		        {731520, uint256S("0x5550f8dd5325e477140b7bce941c47d46c97f26344006c4ab36b6db63caab896")},
		        {760320, uint256S("0x479416d69a39b40f82055a36ced8fde8bff7cc9488d88c4c51adb327bdfa2dbc")},
		        {789120, uint256S("0xa5286d30fc85315092839b73630c2463c683e4b6d698140dda6938752a250025")},
		        {817920, uint256S("0xef7aa22745d200dd6966995139e3ef35ebd97561f32555bfdeada1c2cdbce8be")},
		        {846720, uint256S("0x16590b7ad48ea99a484e1c2fa686895623c4bb9ed14d832717351a588cad742b")},
		        {875520, uint256S("0x1b15368afbefac00ea2833cd0dc486464f7a2bc45cf849863d8ecbb959c343f3")},
		        {904320, uint256S("0x91a89c6516c90db046e458484c2e72b91fbad522b7abc727dd12d500645a5969")},
		        {933120, uint256S("0x48365c2a8bed4d5052d49550378c681ea2570a95c76317a4d182090be7272127")},
		        {961920, uint256S("0x5dd8e1fbbfb66b4919d880ca374de804ddb7673d0a5b9cb231e6b1470a73d7d0")},
		        {990720, uint256S("0x7a14741c8b5c10eab3464cd23b65554f1bc5c940e2ccb69461802e61e4f73b96")},
	            {1019520, uint256S("0xab7a59f310e2e86d81af0ca1f608d24127d8af934825c34ba3897eab1ab398cf")},
	            {1048320, uint256S("0xc12e7cae889b0dd49f6d3d39fc40ff7ec5aadbfffb20d6ac4cb461c05f88e638")},
	            {1077120, uint256S("0x259ec9e319169f587e3f9f8e38a0bfd5ca0cbc33a1e7c05c51b9b93fd1d17458")},
	            {1134720, uint256S("0x84d59c3b22dc90f04e5b9b6049431a8049af875287b7df1df8f5ecd8566124e9")},
	            {1221120, uint256S("0x2471f5f64406e4af10752ae690df1243bbaa27a17e8c30c1c85f7216bbec58ec")},
	            {1307520, uint256S("0xb48ffde81935649c3a9d8ba691f784436fe05dd802a72afbeea9923d417f774e")},
	            {1330560, uint256S("0xbe3a8b802886b0ae2f36e7bf225c11ae908b9e22756d6d981bc8e77a115d611a")},
	            {1589760, uint256S("0x7a6a309be61a45470a168f9b5ba3ce09525b404e23f1729d5740458b4bd0a5a2")},
	            {1618560, uint256S("0xf8b54d3d99bae69dd65740e2e8a1bb265dac0b7de46c393a7930af187cfea19e")},
	            {1647360, uint256S("0xbffe5af1ccc7831490d5d265116d92b30ab805dcd44d273e942e495b6bb3acd2")},
	            {1704960, uint256S("0xf260df4815a191212962ffe2e9d730c2365beb6a1b16515a7553d80987e2a8c9")},
	            {1820160, uint256S("0x67c14f74e3b52c7744786d014e25c27270203d8b6f4ec5081f5deb371262e635")},
	            {2368300, uint256S("0x79c6f56bff70c17a2ea17b926f0abb3af1f017348ab796cd29be7fb00327bf1d")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 2368300.
            1637955350, // * UNIX timestamp of last known number of transactions
            29474397,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.4     // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 293368;
        consensus.BIP34Hash = uint256S("00000002c0b976c7a5c9878f1cec63fb4d88d68d614aedeaf8158c42d904795e");
        consensus.powLimit =            uint256S("0000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 28;
        consensus.bnInitialHashTarget = uint256S("00000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 29;

        consensus.nTargetTimespan = 7 * 24 * 60 * 60;  // one week
        consensus.nStakeTargetSpacing = 10 * 60;  // 10-minute block spacing
        consensus.nTargetSpacingWorkMax = 12 * consensus.nStakeTargetSpacing; // 2-hour
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing;
        consensus.nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nModifierInterval = 60 * 20; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 60;

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000002e9e7b00e1f6dc5123a04aad68dd0f0968d8c7aa45f6640795c37b1"); //1135275

        pchMessageStart[0] = 0xcb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;
        vAlertPubKey = ParseHex("04383862439513e940f6fcbf62d365c162a5256920c2c25b0b4266fdee4a443d71cfe224dbccff6fdb2ea57a37eb0cbec5637ebea06f63c70ca093672fbdc27643");
        nDefaultPort = 9903;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1345083810, 1345090000, 122894938, 0x1d0fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06"));
        assert(genesis.hashMerkleRoot == uint256S("0x3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("tseed.peercoin.net");
        vSeeds.emplace_back("tseed2.peercoin.net");
        vSeeds.emplace_back("tseed.peercoin-library.org");
        vSeeds.emplace_back("testseed.ppcoin.info");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // human readable prefix to bench32 address
        bech32_hrp = "tpc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {     0, uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06")},
                { 19080, uint256S("0xb054d63d41852d71b611eaa8eca37d9fddca69b5013cf0966d453402ec8005ce")},
                { 30583, uint256S("0x5179c0c496b5d25ab81ffe14273ea6928c6ff81c0a0d6a83b5d7d41d64886300")},
                { 99999, uint256S("0xa7b03b14b8673683d972ab81775f3e85fea4fe689874b5956183466535dc651c")},
                {219999, uint256S("0x0691bb86c92762c5c4c5a3723585ebeb7ec59310bbb0bdb6666551ab24ad919e")},
                {336000, uint256S("0xf07adf61615c529f7c282b858d13d3e037b197324cb12e0669c461947494c4e3")},
                {372751, uint256S("0x000000000000148db599b217c117b5104f5043c55f6ca2a8a065d9fab9f9bba1")},
                {382019, uint256S("0x3ab75769d7957d9bf0857b5019d0a0e41044fa9ecf30b2f9c32aa457b0864ce5")},
                {408500, uint256S("0x1636ac08b073d26b28fa40243d58dd5deb215752efe094c92c61998e4e9baf3f")},
                {412691, uint256S("0x0e20318be88f07f521453435b37cfc516c3de07264a78ed7170985a1126126ab")},
                {441667, uint256S("0x4636d75163248acd32c212bd1b17f556bdeb3f40316eef662f6736d1c529ae07")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 4636d75163248acd32c212bd1b17f556bdeb3f40316eef662f6736d1c529ae07 (height 441667)
            1580809121, // * UNIX timestamp of last known number of transactions
            861789,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.003670629 // * estimated number of transactions per second after that timestamp
                        // 861789/(1580809121-1346029522) = 0.003670629
        };
    }
};

/**
 * Regression test
 */

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.powLimit =            uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 28;
        consensus.bnInitialHashTarget = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~arith_uint256(0) >> 29;

        consensus.nTargetTimespan = 7 * 24 * 60 * 60; // two weeks
        consensus.nStakeTargetSpacing = 10 * 60; // 10-minute block spacing
        consensus.nTargetSpacingWorkMax = 12 * consensus.nStakeTargetSpacing; // 2-hour
        consensus.nPowTargetSpacing = consensus.nStakeTargetSpacing;

        consensus.nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day
        consensus.nStakeMaxAge = 60 * 60 * 24 * 90;
        consensus.nModifierInterval = 60 * 20; // Modifier interval: time to elapse before new modifier is computed
        consensus.nCoinbaseMaturity = 60;

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xcb;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;
        vAlertPubKey = ParseHex("04383862439513e940f6fcbf62d365c162a5256920c2c25b0b4266fdee4a443d71cfe224dbccff6fdb2ea57a37eb0cbec5637ebea06f63c70ca093672fbdc27643");
        nDefaultPort = 9903;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1345083810, 1345090000, 122894938, 0x1d0fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06"));
        assert(genesis.hashMerkleRoot == uint256S("0x3c2d8f85fab4d17aac558cc648a1a58acff0de6deb890c29985690052c5993c2"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        checkpointData = {
            {
                {0, uint256S("0x00000001f757bb737f6596503e17cd17b0658ce630cc727c0cca81aec47c9f06")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "pcrt";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
