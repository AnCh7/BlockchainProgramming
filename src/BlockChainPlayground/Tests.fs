namespace BlockChainPlayground

open NUnit.Framework

[<TestFixture>]
type BitcoinTransferTests() = 

    [<Test>]
    member test.BitcoinAddressTest() = 
        let chapter = BitcoinTransfer()
        chapter.BitcoinAddress()

    [<Test>]
    member test.BitcoinAddress2Test() = 
        let chapter = BitcoinTransfer()
        chapter.BitcoinAddress2()

    [<Test>]
    member test.BitcoinAddress3Test() = 
        let chapter = BitcoinTransfer()
        chapter.BitcoinAddress3()

    [<Test>]
    member test.BitcoinAddress4Test() = 
        let chapter = BitcoinTransfer()
        chapter.BitcoinAddress4()

[<TestFixture>]
type TransactionsTests() = 

    [<Test>]
    member test.BlockrTest() = 
        let chapter = Transactions()
        chapter.Blockr()

    [<Test>]
    member test.SpendYourCoinTest() = 
        let chapter = Transactions()
        chapter.SpendYourCoin()

    [<Test>]
    member test.ProofOfOwnershipTest() = 
        let chapter = Transactions()
        chapter.ProofOfOwnership()

    [<Test>]
    member test.ProofOfOwnership2Test() = 
        let chapter = Transactions()
        chapter.ProofOfOwnership2()

[<TestFixture>]
type KeyStorageAndGenerationTests() = 

    [<Test>]
    member test.``Is it random enough? Test``() = 
        let chapter = KeyStorageAndGeneration()
        chapter.``Is it random enough?``()

    [<Test>]
    member test.KeyDerivationFunctionTest() = 
        let chapter = KeyStorageAndGeneration()
        chapter.KeyDerivationFunction()

    [<Test>]
    member test.KeyEncryptionTest() = 
        let chapter = KeyStorageAndGeneration()
        chapter.KeyEncryption()

    [<Test>]
    member test.BIP38Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.BIP38()

    [<Test>]
    member test.BIP32Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.BIP32()

    [<Test>]
    member test.BIP44Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.BIP44()

    [<Test>]
    member test.HardenedTest() = 
        let chapter = KeyStorageAndGeneration()
        chapter.Hardened()

    [<Test>]
    member test.NonHardenedTest() = 
        let chapter = KeyStorageAndGeneration()
        chapter.NonHardened()

    [<Test>]
    member test.Derivate1Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.Derivate1()

    [<Test>]
    member test.Derivate2Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.Derivate2()

    [<Test>]
    member test.BIP39Test() = 
        let chapter = KeyStorageAndGeneration()
        chapter.BIP39()

    [<Test>]
    member test.DarkWalletTest() = 
        let chapter = KeyStorageAndGeneration()
        chapter.DarkWallet()

[<TestFixture>]
type OtherTypesOfOwnershipTests() = 

    [<Test>]
    member test.``P2PK[H] Tests``() = 
        let chapter = OtherTypesOfOwnership()
        chapter.``P2PK[H]``()

    [<Test>]
    member test.MultiSigTest() = 
        let chapter = OtherTypesOfOwnership()
        chapter.MultiSig()

    [<Test>]
    member test.P2SHTest() = 
        let chapter = OtherTypesOfOwnership()
        chapter.P2SH()

    [<Test>]
    member test.ArbitraryTest() = 
        let chapter = OtherTypesOfOwnership()
        chapter.Arbitrary()

    [<Test>]
    member test.TransactionBuilderTest() = 
        let chapter = OtherTypesOfOwnership()
        chapter.TransactionBuilder()

    [<Test>]
    member test.``TransactionBuilder P2SH Test``() = 
        let chapter = OtherTypesOfOwnership()
        chapter.``TransactionBuilder P2SH``()

    [<Test>]
    member test.``TransactionBuilder Stealth Coin Test``() = 
        let chapter = OtherTypesOfOwnership()
        chapter.``TransactionBuilder Stealth Coin``()

[<TestFixture>]
type OtherTypesOfAssetTests() = 

    [<Test>]
    member test.ColoredCoinsTests() = 
        let chapter = OtherTypesOfAsset()
        chapter.ColoredCoins()

    [<Test>]
    member test.TransferAssetsTests() = 
        let chapter = OtherTypesOfAsset()
        chapter.TransferAsset()

    [<Test>]
    member test.UnitTestsTests() = 
        let chapter = OtherTypesOfAsset()
        chapter.UnitTests()

    [<Test>]
    member test.LiquidDemocracyTests() = 
        let chapter = OtherTypesOfAsset()
        chapter.LiquidDemocracy()

    [<Test>]
    member test.ProofOfBurnAndReputationTests() = 
        let chapter = OtherTypesOfAsset()
        chapter.ProofOfBurnAndReputation()
