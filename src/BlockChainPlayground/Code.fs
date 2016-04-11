namespace BlockChainPlayground

open NBitcoin
open NBitcoin.Crypto
open NBitcoin.Protocol
open NBitcoin.Stealth
open NBitcoin.DataEncoders
open NBitcoin.OpenAsset
open System
open System.Linq
open System.Text
open System.Threading
open System.Collections.Generic

type BitcoinTransfer() = 

    member __.BitcoinAddress() = 

        // Generates a new private key
        let key = Key()

        // Gets the matching public key
        let pubKey = key.PubKey
        printfn "Public Key : %O" pubKey

        let hash = pubKey.Hash
        printfn "Hashed public key : %O" hash

        // Retrieves the bitcoin address
        let address = pubKey.GetAddress Network.TestNet
        printfn "Address : %O" address

        let scriptPubKeyAddress = address.ScriptPubKey
        printfn "ScriptPubKey from address : %O" scriptPubKeyAddress

        let scriptPubKeyHash = hash.ScriptPubKey
        printfn "ScriptPubKey from hash : %O" scriptPubKeyHash

    member __.BitcoinAddress2() = 

        let scriptPubKey = Script "OP_DUP OP_HASH160 1b2da6ee52ac5cd5e96d2964f12a0241851f8d2a OP_EQUALVERIFY OP_CHECKSIG"
        let address = scriptPubKey.GetDestinationAddress Network.TestNet
        printfn "Bitcoin Address : %O" address

    member __.BitcoinAddress3() = 

        let scriptPubKey = Script "OP_DUP OP_HASH160 1b2da6ee52ac5cd5e96d2964f12a0241851f8d2a OP_EQUALVERIFY OP_CHECKSIG"

        let hash = scriptPubKey.GetDestination()
        let keyId = downcast hash : KeyId
        printfn "Public Key Hash : %O" keyId

        let address = BitcoinPubKeyAddress (keyId, Network.TestNet)
        printfn "Bitcoin Address : %O" address

    member __.BitcoinAddress4() = 

        let key = Key()
        let secret = key.GetBitcoinSecret Network.TestNet
        printfn "Bitcoin Secret: %O" secret

        let secret2 = BitcoinSecret "KyVVPaNYFWgSCwkvhMG3TruG1rUQ5o7J3fX7k8w7EepQuUQACfwE"
        printfn "Bitcoin Secret: %O" secret2

type Transactions() = 

    member __.Blockr() = 

        let blockr = BlockrTransactionRepository()
        let transaction = blockr.Get "4f3e2508cc9085f354e560cfd67bca22939b07ba8a694046242acb94b70e6ef3"
        printfn "Transaction: %O" transaction

    member __.SpendYourCoin() = 

        let blockr = BlockrTransactionRepository Network.TestNet

        // Previous transaction
        let previousTransaction = blockr.Get "9f2cccd5c11339982afdb5bca440cfa92572f3ce91232e0901294a665419a1eb"
        printfn "Transaction: %O" previousTransaction

        // Adding previous transaction reference
        let payment = Transaction()
        let outpoint = OutPoint(previousTransaction.GetHash(), 1)
        let txIn = TxIn outpoint
        payment.Inputs.Add txIn

        // Sending address
        let sendingSecret = BitcoinSecret "cNZX2aQr3qMBp4xGZVEYNkuvHaBrLaB6mDsErxV6MHwH5Tjnt1t2"
        let sendingAddress = sendingSecret.GetAddress()

        // Receiving address
        let receivingSecret = BitcoinSecret "KxRD5Lw4UQxa6D2pNkirt2hB7YMgHQnJf3UNs38Cd3Svet2nqSbW"
        let receivingAddress = receivingSecret.GetAddress()

        // Send to new address
        let txOut = TxOut()
        txOut.Value <- Money.Coins 0.006m
        txOut.ScriptPubKey <- receivingAddress.ScriptPubKey
        payment.Outputs.Add txOut

        // Send back to main
        let txOut2 = TxOut()
        txOut2.Value <- Money.Coins 0.090m
        txOut2.ScriptPubKey <- sendingSecret.ScriptPubKey
        payment.Outputs.Add txOut2

        // Test message
        let txOut3 = TxOut()
        txOut3.Value <- Money.Zero
        txOut3.ScriptPubKey <- TxNullDataTemplate.Instance.GenerateScriptPubKey (Encoding.UTF8.GetBytes "Testing")
        payment.Outputs.Add txOut3

        // Signing
        payment.Inputs.[0].ScriptSig <- sendingAddress.ScriptPubKey
        // payment.Inputs.[0].ScriptSig <- fundingTransaction.Outputs.[1].ScriptPubKey;
        payment.Sign(sendingSecret, false)

        printfn "Payment: %O" payment

        // Send transaction
        // Connect to the node
        use node = Node.ConnectToLocal Network.TestNet

        // Say hello
        node.VersionHandshake()

        // Advertize your transaction (send just the hash)
        node.SendMessage(InvPayload(InventoryType.MSG_TX, payment.GetHash()))

        // Send it
        node.SendMessage(TxPayload payment)

        // Wait a bit
        Thread.Sleep 500

    member __.ProofOfOwnership() = 

        let address = BitcoinPubKeyAddress "1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB"
        let msg = "Nicolas Dorier Book Funding Address"
        let signature = "H1jiXPzun3rXi0N9v9R5fAWrfEae9WPmlL5DJBj1eTStSvpKdRR8Io6/uT9tGH/3OnzG6ym5yytuWoA9ahkC3dQ="

        let verify msg signature = address.VerifyMessage (msg, signature)
        printfn "Verification: %O" (verify msg signature)

    member __.ProofOfOwnership2() = 
        
        let mySmallAddressSecret = BitcoinSecret "KxbcxaYG91UeJMMmXjc3dPcQ44JfFB4tbt3qnbQipddEnE2xNznc"
        let mySmallAddress = mySmallAddressSecret.GetAddress() // 1BpjkTdPKv2r9xMzx5kdvhYdv89tJjgK7a

        let msg = "Prove me you are 1BpjkTdPKv2r9xMzx5kdvhYdv89tJjgK7a"
        let signature = mySmallAddressSecret.PrivateKey.SignMessage msg

        let verify msg signature = mySmallAddress.VerifyMessage (msg, signature)

        printfn "Verification: %O" (verify msg signature)

type KeyStorageAndGeneration() = 
    
    member __.``Is it random enough?``() = 

        RandomUtils.AddEntropy "hello"
        let array = [| 1uy; 2uy; 3uy |]

        RandomUtils.AddEntropy array
        let nsaProofKey = Key()

        printfn "Key: %O" nsaProofKey.ScriptPubKey
    
    member __.KeyDerivationFunction() = 

        let array = [| 1uy; 2uy; 3uy |]
        let derived = SCrypt.BitcoinComputeDerivedKey("hello", array)
        RandomUtils.AddEntropy derived
        printfn "derived: %O" derived
    
    member __.KeyEncryption() = 

        let key = Key()

        let mutable wif = key.GetBitcoinSecret Network.Main
        printfn "wif: %O" wif

        let encrypted = wif.Encrypt "secret"
        printfn "encrypted: %O" encrypted

        wif <- encrypted.GetSecret "secret"
        printfn "encrypted wif: %O" wif

    member __.BIP38() = 

        let passphraseCode = BitcoinPassphraseCode("my secret", Network.Main, null)
        let encryptedKey1 = passphraseCode.GenerateEncryptedSecret()
        printfn "encryptedKey1.GeneratedAddress: %O" encryptedKey1.GeneratedAddress
        printfn "encryptedKey1.EncryptedKey: %O" encryptedKey1.EncryptedKey
        printfn "encryptedKey1.ConfirmationCode: %O" encryptedKey1.ConfirmationCode

        let check = encryptedKey1.ConfirmationCode.Check("my secret", encryptedKey1.GeneratedAddress)
        printfn "check %O" check

        let privateKey = encryptedKey1.EncryptedKey.GetSecret "my secret"
        let addressEquals = (upcast privateKey.GetAddress() : BitcoinAddress) = encryptedKey1.GeneratedAddress
        printfn "addressEquals %O" addressEquals
        printfn "privateKey %O" privateKey

    member __.BIP32() = 

        let mutable masterKey = ExtKey()
        printfn "Master key : %s" (masterKey.ToString(Network.Main))

        for i = 1 to 5 do
            let key = masterKey.Derive  (Convert.ToUInt32 i)
            printfn "Key %O : %O" i (key.ToString(Network.Main))

        let mutable masterPubKey = masterKey.Neuter()

        for i = 1 to 5 do
            let key = masterPubKey.Derive (Convert.ToUInt32 i)
            printfn "PubKey %O : %O" i (key.ToString(Network.Main))

        masterKey <- ExtKey()
        masterPubKey <- masterKey.Neuter()

        //The payment server generate pubkey1
        let pubkey1 = masterPubKey.Derive(Convert.ToUInt32 1)

        //You get the private key of pubkey1
        let key1 = masterKey.Derive(Convert.ToUInt32 1);

        //Check it is legit
        printfn "Generated address :  %O" (pubkey1.PubKey.GetAddress Network.Main)
        printfn "Expected address :  %O" (key1.PrivateKey.PubKey.GetAddress Network.Main)

    member __.BIP44() = 

        let parent = ExtKey()
        let child11 = parent.Derive(1ul).Derive(1ul)
        printfn "child11 : %O" child11.ScriptPubKey
        
        // Or
        
        let parent = ExtKey()
        let child11 = parent.Derive(KeyPath "1/1")
        printfn "child11 : %O" child11.ScriptPubKey

    member __.Hardened() = 

        let ceoKey = ExtKey()
        printfn "CEO : %O" (ceoKey.ToString Network.Main)
        
        let accountingKey = ceoKey.Derive(0, false)
        
        let ceoPubkey = ceoKey.Neuter()
        //Recover ceo key with accounting private key and ceo public key
        let ceoKeyRecovered = accountingKey.GetParentExtKey(ceoPubkey)
        printfn "CEO recovered : %O" (ceoKeyRecovered.ToString(Network.Main))

    member __.NonHardened() = 

        let ceoKey = ExtKey()
        printfn "CEO : %O" (ceoKey.ToString(Network.Main))

        let accountingKey = ceoKey.Derive(0, true)
        let ceoPubkey = ceoKey.Neuter()
        let ceoKeyRecovered = accountingKey.GetParentExtKey(ceoPubkey)

        printfn "Crash"

    member __.Derivate1() = 

        let nonHardened = KeyPath "1/2/3"
        let hardened = KeyPath "1/2/3'"

        printfn "nonHardened : %O" nonHardened.IsHardened
        printfn "hardened : %O" hardened.IsHardened

    member __.Derivate2() = 
        
        let ceoKey = ExtKey()
        let accounting = "1'"
        let customerId = 5
        let paymentId = 50

        //Path : "1'/5/50"
        let path = KeyPath(accounting + "/" + string customerId + "/" + string paymentId)

        let paymentKey = ceoKey.Derive path
        printfn "paymentKey : %O" paymentKey.ScriptPubKey

    member __.BIP39() = 

        let mutable mnemo = Mnemonic(Wordlist.English, WordCount.Twelve)
        let mutable hdRoot = mnemo.DeriveExtKey "my password"
        printfn "mnemo : %O" mnemo

        mnemo <- Mnemonic("minute put grant neglect anxiety case globe win famous correct turn link", Wordlist.English)
        hdRoot <- mnemo.DeriveExtKey "my password"

    member __.DarkWallet() = 

        let scanKey = Key()
        let spendKey = Key()
        let stealthAddress = BitcoinStealthAddress(scanKey.PubKey, [| spendKey.PubKey |], 1, null, Network.Main)
        printfn "stealthAddress : %O" stealthAddress

        let ephemKey = Key()
        let transaction = Transaction()
        stealthAddress.SendTo(transaction, Money.Coins 1.0m, ephemKey)
        printfn "transaction : %O" transaction

        let transaction = Transaction()
        stealthAddress.SendTo(transaction, Money.Coins 1.0m)
        printfn "transaction : %O" transaction

type OtherTypesOfOwnership() = 
    
    member __.``P2PK[H]``() = 

        let mutable key = Key()
        let address = key.PubKey.GetAddress Network.Main
        printfn "address.ScriptPubKey : %O" address.ScriptPubKey

        let genTx = Network.Main.GetGenesis().Transactions.[0].ToString()
        printfn "Genesis Tx : %O" genTx

        key <- Key()
        printfn "Pay to public key : %O" key.PubKey.ScriptPubKey
        printfn "Pay to public key hash : %O" key.PubKey.Hash.ScriptPubKey

    member __.MultiSig() = 

        let bob = Key()
        let alice = Key()
        let satoshi = Key()
        let scriptPubKey = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, [| bob.PubKey; alice.PubKey; satoshi.PubKey |])
        printfn "scriptPubKey : %O" scriptPubKey

        let received = Transaction()
        received.Outputs.Add(TxOut(Money.Coins 1.0m, scriptPubKey))
        let coin = received.Outputs.AsCoins().First()

        let key = Key()
        let nico = key.PubKey.GetAddress Network.Main

        let mutable builder = TransactionBuilder()
        let unsigned = builder.AddCoins(coin).Send(nico, Money.Coins 1.0m).BuildTransaction(false)

        builder <- TransactionBuilder()
        let aliceSigned = builder.AddCoins(coin).AddKeys(alice).SignTransaction unsigned

        builder <- TransactionBuilder()
        let satoshiSigned = builder.AddCoins(coin).AddKeys(satoshi).SignTransaction unsigned

        builder <- TransactionBuilder()
        let fullySigned = builder.AddCoins(coin).CombineSignatures(satoshiSigned, aliceSigned)
        printfn "fullySigned : %O" fullySigned

    member __.P2SH() = 

        let bob = Key()
        let alice = Key()
        let satoshi = Key()
        let redeemScript = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, [| bob.PubKey; alice.PubKey; satoshi.PubKey |])
        printfn "redeemScript : %O" redeemScript.Hash.ScriptPubKey

        let addresss = redeemScript.Hash.GetAddress Network.Main
        printfn "addresss : %O" addresss

        let received = Transaction()

        //Pay to the script hash
        received.Outputs.Add(TxOut(Money.Coins 1.0m, redeemScript.Hash))

        //Give the redeemScript to the coin for Transaction construction and signing
        let coin = received.Outputs.AsCoins().First().ToScriptCoin(redeemScript)
        printfn "coin : %O" coin

    member __.Arbitrary() = 

        let address = BitcoinAddress.Create "1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB"
        let birth = Encoding.UTF8.GetBytes "18/07/1988"
        let birthHash = Hashes.Hash256 birth
        let redeemScript = Script("OP_IF " + "OP_HASH256 " + string (Op.GetPushOp(birthHash.ToBytes())) + 
                                  " OP_EQUAL " + "OP_ELSE " + string address.ScriptPubKey + " " + "OP_ENDIF")

        // Let’s say I sent money to such redeemScript
        let tx = Transaction()
        tx.Outputs.Add(TxOut(Money.Parse "0.0001", redeemScript.Hash))
        let scriptCoin = tx.Outputs.AsCoins().First().ToScriptCoin(redeemScript)

        // So let’s create a transaction that want to spend such output
        // Create spending transaction
        let spending = Transaction()
        let txIn = spending.AddInput(TxIn(OutPoint(tx, 0)))

        // Option 1 : Spender knows my birthdate
        let pushBirthdate = Op.GetPushOp birth
        let selectIf = OpcodeType.OP_1
        let mutable redeemBytes = Op.GetPushOp(redeemScript.ToBytes())
        let mutable scriptSig = Script(pushBirthdate, Op.op_Implicit selectIf, redeemBytes)
        spending.Inputs.[0].ScriptSig <- scriptSig
        
        // Verify the script pass
        let result = spending.Inputs.AsIndexedInputs().First().VerifyScript(tx.Outputs.[0].ScriptPubKey)
        printfn "result : %O" result

        // Option 2 : Spender knows my private key
        let secret = BitcoinSecret "KyVVPaNYFWgSCwkvhMG3TruG1rUQ5o7J3fX7k8w7EepQuUQACfwE"
        let signature = spending.SignInput(secret, scriptCoin)
        let p2pkhProof = PayToPubkeyHashTemplate.Instance.GenerateScriptSig(signature, secret.PrivateKey.PubKey)
        let selectIf2 = OpcodeType.OP_0
        scriptSig <- p2pkhProof + Op.op_Implicit selectIf2 + redeemBytes
        spending.Inputs.[0].ScriptSig <- scriptSig
        
        // Verify the script pass
        let result2 = spending.Inputs.AsIndexedInputs().First().VerifyScript(tx.Outputs.[0].ScriptPubKey)
        printfn "result2 : %O" result2
    
    member __.TransactionBuilder() = 

        // Let’s say that the transaction has a P2PKH, P2PK, and multi sig coin of Bob and Alice.
        let bob = Key()
        let alice = Key()
        let bobAlice = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, bob.PubKey, alice.PubKey)

        let init = Transaction()
        init.Outputs.Add(TxOut(Money.Coins 1.0m, alice.PubKey))
        init.Outputs.Add(TxOut(Money.Coins 1.0m, bob.PubKey.Hash))
        init.Outputs.Add(TxOut(Money.Coins 1.0m, bobAlice))

        // They want to use the coins of this transaction to pay Satoshi, they have to get the coins.
        let satoshi = Key()
        let coins = init.Outputs.AsCoins().ToArray()

        let aliceCoin = coins.[0]
        let bobCoin = coins.[1]
        let bobAliceCoin = coins.[2]

        // Now let’s say bob wants to sends 0.2 BTC, Alice 0.3 BTC, and they agree to use bobAlice to sends 0.5 BTC.
        let builder = TransactionBuilder()
        let tx = builder.AddCoins(bobCoin)
                        .AddKeys(bob)
                        .Send(satoshi, Money.Coins 0.2m)
                        .SetChange(bob)
                        .Then()
                        .AddCoins(aliceCoin)
                        .AddKeys(alice)
                        .Send(satoshi, Money.Coins 0.3m)
                        .SetChange(alice)
                        .Then()
                        .AddCoins(bobAliceCoin)
                        .AddKeys(bob, alice)
                        .Send(satoshi, Money.Coins 0.5m)
                        .SetChange(bobAlice)
                        .SendFees(Money.Coins 0.0001m)
                        .BuildTransaction(true)

        // Then you can verify it is fully signed and ready to send to the network.
        let verify = builder.Verify tx
        printfn "verify : %O" verify

    member __.``TransactionBuilder P2SH``() = 

        let bob = Key()
        let alice = Key()
        let bobAlice = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, bob.PubKey, alice.PubKey)

        let init = Transaction()
        init.Outputs.Add(TxOut(Money.Coins 1.0m, bobAlice.Hash))

        let satoshi = Key()

        let coins = init.Outputs.AsCoins().ToArray()
        let bobAliceScriptCoin = coins.[0].ToScriptCoin bobAlice
        
        // Then the signature
        let builder = TransactionBuilder()
        let tx = builder.AddCoins(bobAliceScriptCoin)
                        .AddKeys(bob, alice)
                        .Send(satoshi, Money.Coins 1.0m)
                        .SetChange(bobAlice.Hash)
                        .BuildTransaction(true)

        let verify = builder.Verify tx
        printfn "verify : %O" verify

    member __.``TransactionBuilder Stealth Coin``() = 
        
        let bob = Key()
        let alice = Key()
        let bobAlice = PayToMultiSigTemplate.Instance.GenerateScriptPubKey(2, bob.PubKey, alice.PubKey)

        let satoshi = Key()
        let scanKey = Key()
        let darkAliceBob = BitcoinStealthAddress(scanKey.PubKey, [| alice.PubKey; bob.PubKey |], 2, null, Network.Main);

        // Someone sent to darkAliceBob
        let init = Transaction()

        darkAliceBob.SendTo(init, Money.Coins 1.0m)
        
        // Get the stealth coin with the scanKey
        let stealthCoin = StealthCoin.Find(init, darkAliceBob, scanKey)
        
        // Spend it
        let builder = TransactionBuilder()
        let tx = builder.AddCoins(stealthCoin)
                        .AddKeys(bob, alice, scanKey)
                        .Send(satoshi, Money.Coins 1.0m)
                        .SetChange(bobAlice.Hash)
                        .BuildTransaction(true)
        
        let verify = builder.Verify tx
        printfn "verify : %O" verify

type OtherTypesOfAsset() = 

    member __.ColoredCoins() = 

        // Here is how to create my issuance coin
        let coin = Coin(uint256 "eb49a599c749c82d824caf9dd69c4e359261d49bbb0b9d6dc18c59bc9214e43b", 
                        0ul, 
                        Money.Satoshis 2000000m, 
                        Script(Encoders.Hex.DecodeData "76a914c81e8e7b7ffca043b088a992795b15887c96159288ac"))
        let issuance = IssuanceCoin coin
        printfn "issuance : %O" issuance

        // Now I need to build transaction and sign the transaction with the help of the TransactionBuilder
        let mutable nico = BitcoinAddress.Create("15sYbVpRh6dyWycZMwPdxJWD4xbfxReeHe");
        let bookKey = BitcoinSecret "KyVVPaNYFWgSCwkvhMG3TruG1rUQ5o7J3fX7k8w7EepQuUQACfwE"
        let builder = TransactionBuilder()
        let tx = builder.AddKeys(bookKey)
                        .AddCoins(issuance)
                        .IssueAsset(nico, AssetMoney(issuance.AssetId, 10))
                        .SendFees(Money.Coins 0.0001m)
                        .SetChange(bookKey.GetAddress())
                        .BuildTransaction(true)
        
        printfn "tx : %O" tx

        use node = Node.ConnectToLocal Network.Main
        node.VersionHandshake()
        node.SendMessage(InvPayload(InventoryType.MSG_TX, tx.GetHash()));
        node.SendMessage(TxPayload tx)
        Thread.Sleep 500

        nico <- BitcoinAddress.Create "15sYbVpRh6dyWycZMwPdxJWD4xbfxReeHe"
        let coloredAddress = nico.ToColoredAddress()
        printfn "coloredAddress : %O" coloredAddress

        let book = BitcoinAddress.Create "1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB"
        let assetId = AssetId(book).GetWif Network.Main
        printfn "assetId : %O" assetId

    member __.TransferAsset() = 

        // Here is how to create my issuance coin
        let coin = Coin(uint256 "fa6db7a2e478f3a8a0d1a77456ca5c9fa593e49fd0cf65c7e349e5a4cbe58842",
                        0ul,
                        Money.Satoshis 2000000m,
                        Script(Encoders.Hex.DecodeData "76a914356fac-dac5f5bcae995d13e667bb5864fd1e7d5988ac"))
        let assetId = BitcoinAssetId "AVAVfLSb1KZf9tJzrUVpktjxKUXGxUTD4e"

        let colored = coin.ToColoredCoin(assetId, uint64 10)
        printfn "colored : %O" colored

        let book = BitcoinAddress.Create "1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB"
        let nicoSecret = BitcoinSecret "KyVVPaNYFWgSCwkvhMG3TruG1rUQ5o7J3fX7k8w7EepQuUQACfwE"
        let nico = nicoSecret.GetAddress() //15sYbVpRh6dyWycZMwPdxJWD4xbfxReeHe
        let forFees = Coin(uint256("7f296e96ec3525511b836ace0377a9fbb723a47bdfb07c6bc3a6f2a0c23eba26"),
                           0ul,
                           Money.Satoshis 4425000m,
                           Script(Encoders.Hex.DecodeData "76a914356facdac5f5bcae995d13e667bb5864fd1e7d5988ac"))
        let builder = TransactionBuilder()
        
        let tx = builder.AddKeys(nicoSecret)
                        .AddCoins(colored, forFees)
                        .SendAsset(book, AssetMoney(AssetId assetId, 10))
                        .SetChange(nico)
                        .SendFees(Money.Coins 0.0001m)
                        .BuildTransaction(true)
        printfn "tx : %O" tx

    member __.UnitTests() = 

        let gold = Key()
        let silver = Key()
        let goldId = gold.PubKey.ScriptPubKey.Hash.ToAssetId()
        let silverId = silver.PubKey.ScriptPubKey.Hash.ToAssetId()

        let bob = Key()
        let alice = Key()
        let satoshi = Key()

        let init = Transaction()
        init.Outputs.Add(TxOut(Money.Parse "1.0", gold))
        init.Outputs.Add(TxOut(Money.Parse "1.0", silver))
        init.Outputs.Add(TxOut(Money.Parse "1.0", satoshi))

        let repo = NoSqlColoredTransactionRepository()
        repo.Transactions.Put(init)
        let mutable color = ColoredTransaction.FetchColors(init, repo)
        printfn "color : %O" color

        // Let’s use the two coins sent to Silver and Gold as Issuance Coins
        let issuanceCoins = init.Outputs
                                .AsCoins()
                                .Take(2)
                                .Select(fun c -> IssuanceCoin(c))
                                .OfType<ICoin>()
                                .ToArray()

        // From that you can send Gold to Satoshi with the TransactionBuilder
        let builder = TransactionBuilder()
        let sendGoldToSatoshi = builder.AddKeys(gold)
                                       .AddCoins(issuanceCoins.[0])
                                       .IssueAsset(satoshi, AssetMoney(goldId, 10))
                                       .SetChange(gold)
                                       .BuildTransaction(true);
        repo.Transactions.Put(sendGoldToSatoshi);
        color <- ColoredTransaction.FetchColors(sendGoldToSatoshi, repo);
        printfn "color : %O" color

        // Firstly, he will fetch the ColoredCoin out of the transaction
        let goldCoin = ColoredCoin.Find(sendGoldToSatoshi, color).FirstOrDefault()
        
        let builder2 = TransactionBuilder()
        let sendToBobAndAlice = builder2.AddKeys(satoshi)
                                        .AddCoins(goldCoin)
                                        .SendAsset(alice, AssetMoney(goldId, 4))
                                        .SetChange(satoshi)
                                        .BuildTransaction(true)

        let satoshiBtc = init.Outputs.AsCoins().Last()
        let builder3 = new TransactionBuilder()
        let sendToAlice = builder3.AddKeys(satoshi)
                                  .AddCoins(goldCoin, satoshiBtc)
                                  .SendAsset(alice, AssetMoney(goldId, 4))
                                  .SetChange(satoshi)
                                  .BuildTransaction(true)

        repo.Transactions.Put(sendToAlice);
        color <- ColoredTransaction.FetchColors(sendToAlice, repo);
        printfn "sendToAlice : %O" sendToAlice
        printfn "color : %O" color

    member __.LiquidDemocracy() = 

        let powerCoin = Key()
        let alice = Key()
        let bob = Key()
        let satoshi = Key()

        let init = Transaction()
        init.Outputs.Add(TxOut(Money.Coins 1.0m, powerCoin))
        init.Outputs.Add(TxOut(Money.Coins 1.0m, alice))
        init.Outputs.Add(TxOut(Money.Coins 1.0m, bob))
        init.Outputs.Add(TxOut(Money.Coins 1.0m, satoshi))

        let repo = NoSqlColoredTransactionRepository()
        repo.Transactions.Put(init)

        let getCoins (tx : Transaction, owner : Key) : IEnumerable<Coin> = tx.Outputs.AsCoins().Where(fun c -> c.ScriptPubKey = owner.ScriptPubKey)

        // Imagine that Alice buy 2 Power coins
        let mutable issuance = getCoins(init, powerCoin).Select(fun c -> IssuanceCoin(c))
        let builder = new TransactionBuilder()
        let toAlice = builder.AddCoins(downcast issuance : IEnumerable<ICoin>)
                             .AddKeys(powerCoin)
                             .IssueAsset(alice, AssetMoney(powerCoin, int64 2))
                             .SetChange(powerCoin)
                             .Then()
                             .AddCoins(downcast getCoins(init, alice) : IEnumerable<ICoin>)
                             .AddKeys(alice)
                             .Send(alice, Money.Coins 0.2m)
                             .SetChange(alice)
                             .BuildTransaction(true)
        repo.Transactions.Put(toAlice)

        // For some reason, Alice, might want to sell some of her voting power to Satoshi
        let builder2 = new TransactionBuilder()
        let toSatoshi = builder2.AddCoins(downcast ColoredCoin.Find(toAlice, repo) : IEnumerable<ICoin>)
                                .AddCoins(downcast getCoins(init, alice) : IEnumerable<ICoin>)
                                .AddKeys(alice)
                                .SendAsset(satoshi, AssetMoney(powerCoin, int64 1))
                                .SetChange(alice)
                                .Then()
                                .AddCoins(downcast getCoins(init, satoshi) : IEnumerable<ICoin>)
                                .AddKeys(satoshi)
                                .Send(alice, Money.Coins 0.1m)
                                .SetChange(satoshi)
                                .BuildTransaction(true);
        repo.Transactions.Put(toSatoshi)

        // First, I need to create some funds for voting coin
        let votingCoin = Key()
        let init2 = new Transaction()
        
        init2.Outputs.Add(TxOut(Money.Coins 1.0m, votingCoin))
        repo.Transactions.Put(init2)

        // Then, issue the voting coins
        issuance <- getCoins(init2, votingCoin).Select(fun c -> new IssuanceCoin(c)).ToArray()
        let builder3 = new TransactionBuilder()
        let toVoters = builder3.AddCoins(downcast issuance : IEnumerable<ICoin>)
                               .AddKeys(votingCoin)
                               .IssueAsset(alice, AssetMoney(votingCoin, int64 1))
                               .IssueAsset(satoshi, AssetMoney(votingCoin, int64 1))
                               .SetChange(votingCoin)
                               .BuildTransaction(true)
        repo.Transactions.Put(toVoters)

        // Alice decision is to handout her voting coin to someone she trusts having a better judgment on
        // financial matter. She chooses to delegate her vote to Bob
        let aliceVotingCoin = ColoredCoin.Find(toVoters, repo).Where(fun c -> c.ScriptPubKey = alice.ScriptPubKey)
        let builder4 = new TransactionBuilder()
        let toBob = builder4.AddCoins(downcast aliceVotingCoin : IEnumerable<ICoin>)
                            .AddKeys(alice)
                            .SendAsset(bob, AssetMoney(votingCoin, int64 1))
                            .BuildTransaction(true)
        repo.Transactions.Put(toBob)

        // Boss says on the company’s website - Send your coins to 1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN for yes 
        // and to 1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV for no.
        // Bob decides that the company should take the loan
        let bobVotingCoin = ColoredCoin.Find(toVoters, repo).Where(fun c -> c.ScriptPubKey = bob.ScriptPubKey)
        let builder5 = new TransactionBuilder()
        let vote = builder5.AddCoins(downcast bobVotingCoin : IEnumerable<ICoin>)
                           .AddKeys(bob)
                           .SendAsset(BitcoinAddress.Create "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN", AssetMoney(votingCoin, int64 1))
                           .BuildTransaction(true)
        printfn "vote : %O" vote

        // Alternative: Use of Ricardian Contract
        issuance <- getCoins(init2, votingCoin).Select(fun c -> new IssuanceCoin(c))
        issuance.First().DefinitionUrl <- Uri "http://boss.com/vote01.json"
        let builder6 = new TransactionBuilder()
        let toVoters = builder6.AddCoins(downcast issuance : IEnumerable<ICoin>)
                                .AddKeys(votingCoin)
                                .IssueAsset(alice, AssetMoney(votingCoin, int64 1))
                                .IssueAsset(satoshi, AssetMoney(votingCoin, int64 1))
                                .SetChange(votingCoin)
                                .BuildTransaction(true)
        repo.Transactions.Put(toVoters)

    member __.ProofOfBurnAndReputation() = 

        let alice = Key()

        // Giving some money to alice
        let init = Transaction()
        init.Outputs.Add(TxOut(Money.Coins 1.0m, alice))

        let coin = init.Outputs.AsCoins().First()
        
        // Burning the coin
        let burn = Transaction()
        let txIn = TxIn(coin.Outpoint)
        txIn.ScriptSig <- coin.ScriptPubKey
        burn.Inputs.Add txIn

        //Spend the previous coin
        let message = "Burnt for \"Alice Bakery\"";
        let opReturn = TxNullDataTemplate.Instance.GenerateScriptPubKey(Encoding.UTF8.GetBytes message)
        burn.Outputs.Add(TxOut(Money.Coins 1.0m, opReturn))
        burn.Sign(alice, false)


