using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.Protocol;
using NBitcoin.Stealth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProgrammingBitcoin
{
    class Program
    {
        static void Main(string[] args)
        {            
            //Code1();

            //Code2();

            //Code3();

            //Code4();

            //new Program().Code5();
            //new Program().Code6();
            //new Program().Code7();
            //new Program().Code8();
            //new Program().Code9();
            //new Program().Code10();
            //new Program().Code11();
            //new Program().Code12();
            //new Program().Code13();

            //new Program().Code14();
            //new Program().Code15();
            //new Program().Code16();
            new Program().Code17();
        }

        private void Code17()
        {
            var bob = new Key();
            var alice = new Key();
            var bobAlice = PayToMultiSigTemplate
                            .Instance
                            .GenerateScriptPubKey(2, bob.PubKey, alice.PubKey);

            Transaction init = new Transaction();
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), alice.PubKey));
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), bob.PubKey.Hash));
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), bobAlice));


            var satoshi = new Key();
            Coin[] coins = init.Outputs.AsCoins().ToArray();

            Coin aliceCoin = coins[0];
            Coin bobCoin = coins[1];
            Coin bobAliceCoin = coins[2];

            var builder = new TransactionBuilder();
            Transaction tx = builder
                 .AddCoins(bobCoin)
                 .AddKeys(bob)
                 .Send(satoshi, Money.Coins(0.2m))
                 .SetChange(bob)
                 .Then()
                 .AddCoins(aliceCoin)
                 .AddKeys(alice)
                 .Send(satoshi, Money.Coins(0.3m))
                 .SetChange(alice)
                 .Then()
                 .AddCoins(bobAliceCoin)
                 .AddKeys(bob, alice)
                 .Send(satoshi, Money.Coins(0.5m))
                 .SetChange(bobAlice)
                 .SendFees(Money.Coins(0.0001m))
                 .BuildTransaction(sign: true);


            Console.WriteLine(builder.Verify(tx));

            init = new Transaction();
            init.Outputs.Add(new TxOut(Money.Coins(1.0m), bobAlice.Hash));

            coins = init.Outputs.AsCoins().ToArray();
            ScriptCoin bobAliceScriptCoin = coins[0].ToScriptCoin(bobAlice);

            builder = new TransactionBuilder();
            tx = builder
                    .AddCoins(bobAliceScriptCoin)
                    .AddKeys(bob, alice)
                    .Send(satoshi, Money.Coins(1.0m))
                    .SetChange(bobAlice.Hash)
                    .BuildTransaction(true);
            Console.WriteLine(builder.Verify(tx));

            Key scanKey = new Key();
            BitcoinStealthAddress darkAliceBob =
                new BitcoinStealthAddress
                    (
                        scanKey: scanKey.PubKey,
                        pubKeys: new[] { alice.PubKey, bob.PubKey },
                        signatureCount: 2,
                        bitfield: null,
                        network: Network.Main
                    );

            //Fake transaction
            init = new Transaction();
            darkAliceBob
                .CreatePayment()
                .AddToTransaction(init, Money.Coins(1.0m));

            //Get the stealth coin with the scanKey
            StealthCoin stealthCoin
                = StealthCoin.Find(init, darkAliceBob, scanKey);

            //Spend it
            tx = builder
                    .AddCoins(stealthCoin)
                    .AddKeys(bob, alice, scanKey)
                    .Send(satoshi, Money.Coins(1.0m))
                    .SetChange(bobAlice.Hash)
                    .BuildTransaction(true);
            Console.WriteLine(builder.Verify(tx));
        }

        private void Code16()
        {
            BitcoinAddress address = new BitcoinPubKeyAddress("1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB");
            var birth = Encoding.UTF8.GetBytes("18/07/1988");
            var birthHash = Hashes.Hash256(birth);
            Script redeemScript = new Script(
                "OP_IF "
                    + "OP_HASH256 " + Op.GetPushOp(birthHash.ToBytes()) + " OP_EQUAL " +
                "OP_ELSE "
                    + address.ScriptPubKey + " " +
                "OP_ENDIF");

            var tx = new Transaction();
            tx.Outputs.Add(new TxOut(Money.Parse("0.0001"), redeemScript.Hash));
            ScriptCoin scriptCoin = tx.Outputs.AsCoins().First().ToScriptCoin(redeemScript);

            //Create spending transaction
            Transaction spending = new Transaction();
            spending.AddInput(new TxIn(new OutPoint(tx, 0)));

            ////Option 1 : Spender knows my birthdate
            ScriptEvaluationContext eval = new ScriptEvaluationContext();
            Op pushBirthdate = Op.GetPushOp(birth);
            Op selectIf = OpcodeType.OP_1; //go to if
            Op redeemBytes = Op.GetPushOp(redeemScript.ToBytes());
            Script scriptSig = new Script(pushBirthdate, selectIf, redeemBytes);
            spending.Inputs[0].ScriptSig = scriptSig;

            //Verify the script pass
            var result = eval.VerifyScript(scriptSig, tx.Outputs[0].ScriptPubKey, spending, 0, null);
            Console.WriteLine(result);
            ///////////

            ////Option 2 : Spender knows my private key
            eval = new ScriptEvaluationContext();
            BitcoinSecret secret = new BitcoinSecret("...");
            var sig = spending.SignInput(secret.PrivateKey, scriptCoin);
            var p2pkhProof = PayToPubkeyHashTemplate
                .Instance
                .GenerateScriptSig(sig, secret.PrivateKey.PubKey);
            selectIf = OpcodeType.OP_0; //go to else
            scriptSig = p2pkhProof + selectIf + redeemBytes;
            spending.Inputs[0].ScriptSig = scriptSig;

            //Verify the script pass
            result = eval.VerifyScript(scriptSig, tx.Outputs[0].ScriptPubKey, spending, 0, null);
            Console.WriteLine(result);
            ///////////
        }

        private void Code15()
        {
            Mnemonic mnemo = new Mnemonic(Wordlist.English);
            ExtKey hdRoot = mnemo.DeriveExtKey("my password");

            Console.WriteLine(mnemo);

            mnemo = new Mnemonic("over coin board extra evoke because major liberty cannon lift code six purity brief universe master soccer wool lion tuition impulse cherry cousin bunker",
                          Wordlist.English);
            hdRoot = mnemo.DeriveExtKey("my password");
        }

        private void Code14()
        {
            Key bob = new Key();
            Key alice = new Key();
            Key satoshi = new Key();

            Script redeemScript =
                PayToMultiSigTemplate
                .Instance
                .GenerateScriptPubKey(2, new[] { bob.PubKey, alice.PubKey, satoshi.PubKey });

            Transaction received = new Transaction();
            //Pay to the script hash
            received.Outputs.Add(new TxOut(Money.Coins(1.0m), redeemScript.Hash));

            TransactionBuilder builder = new TransactionBuilder();

            //Give the redeemScript to the coin for Transaction construction
            //and signing
            ScriptCoin coin = new ScriptCoin(
                new OutPoint(received.GetHash(), 0),
                received.Outputs[0],
                redeemScript
                );

        }

        private void Code13()
        {
            Key bob = new Key();
            Key alice = new Key();
            Key satoshi = new Key();

            var scriptPubKey = PayToMultiSigTemplate
                .Instance
                .GenerateScriptPubKey(2, new[] { bob.PubKey, alice.PubKey, satoshi.PubKey });

            Console.WriteLine(scriptPubKey);

            Transaction received = new Transaction();
            received.Outputs.Add(new TxOut(Money.Coins(1.0m), scriptPubKey));

            TransactionBuilder builder = new TransactionBuilder();
            Coin coin = new Coin(
                new OutPoint(received.GetHash(), 0),
                received.Outputs[0]
                );

            BitcoinAddress nico = new Key().PubKey.GetAddress(Network.Main);
            Transaction unsigned =
                builder
                .AddCoins(coin)
                .Send(nico, Money.Coins(1.0m))
                .BuildTransaction(false);

            builder = new TransactionBuilder();
            Transaction aliceSigned =
                builder
                .AddCoins(coin)
                .AddKeys(alice)
                .SignTransaction(unsigned);

            builder = new TransactionBuilder();
            Transaction satoshiSigned =
                builder
                .AddCoins(coin)
                .AddKeys(satoshi)
                .SignTransaction(unsigned);

            builder = new TransactionBuilder();
            Transaction fullySigned =
                builder
                .AddCoins(coin)
                .CombineSignatures(satoshiSigned, aliceSigned);

            Console.WriteLine(fullySigned);


        }

        private void Code12()
        {
            Key key = new Key();
            BitcoinAddress address = key.PubKey.GetAddress(Network.Main);
            //Console.WriteLine(address.ScriptPubKey);

            Console.WriteLine(Network.Main.GetGenesis().Transactions[0].ToString());

            key = new Key();
            Console.WriteLine("Pay to public key : " + key.PubKey.ScriptPubKey);
            Console.WriteLine();
            Console.WriteLine("Pay to public key hash : " + key.PubKey.Hash.ScriptPubKey);

        }

        private void Code11()
        {
            var scanKey = new Key();
            var spendKey = new Key();
            BitcoinStealthAddress stealthAddress
                = new BitcoinStealthAddress
                    (
                    scanKey: scanKey.PubKey,
                    pubKeys: new[] { spendKey.PubKey },
                    signatureCount: 1,
                    bitfield: null,
                    network: Network.Main);


            var ephem = new Key();
            StealthPayment payment = stealthAddress.CreatePayment(ephem);

            Transaction transaction = new Transaction();
            payment.AddToTransaction(transaction, Money.Coins(1.0m));
            Console.WriteLine(transaction);

            payment = stealthAddress.GetPayments(transaction, scanKey).FirstOrDefault();

            //Optional check (GetPayment already do it)
            BitcoinAddress expectedAddress = payment.StealthKeys[0].GetAddress(Network.Main);
            bool hasPayment = transaction
                .Outputs
                .Any(o => o.ScriptPubKey.GetDestinationAddress(Network.Main) == expectedAddress);
            Console.WriteLine(hasPayment);
            ////

            payment = stealthAddress.GetPayments(transaction, scanKey).FirstOrDefault();
            Key privateKey = spendKey.Uncover(scanKey, payment.Metadata.EphemKey);
            expectedAddress = privateKey.PubKey.GetAddress(Network.Main);
            bool isRightKey = transaction
                .Outputs
                .Any(o => o.ScriptPubKey.GetDestinationAddress(Network.Main) == expectedAddress);
            Console.WriteLine(isRightKey);
        }

        private void Code10()
        {
            ExtKey masterKey = new ExtKey();
            //Console.WriteLine("Master key : " + masterKey.ToString(Network.Main));
            for (int i = 0 ; i < 10 ; i++)
            {
                ExtKey key = masterKey.Derive((uint)i);
                //Console.WriteLine("Key " + i + " : " + key.ToString(Network.Main));
            }

            ExtPubKey masterPubKey = masterKey.Neuter();
            for (int i = 0 ; i < 10 ; i++)
            {
                ExtPubKey pubkey = masterPubKey.Derive((uint)i);
                //Console.WriteLine("PubKey " + i + " : " + pubkey.ToString(Network.Main));
            }

            masterKey = new ExtKey();
            masterPubKey = masterKey.Neuter();

            //The payment server generate pubkey1
            ExtPubKey pubkey1 = masterPubKey.Derive((uint)1);

            //You get the private key of pubkey1
            ExtKey key1 = masterKey.Derive((uint)1);

            //Check it is legit
            //Console.WriteLine("Generated address : " + pubkey1.PubKey.GetAddress(Network.Main));
            //Console.WriteLine("Expected address : " + key1.Key.PubKey.GetAddress(Network.Main));

            ExtKey parent = new ExtKey();
            ExtKey child11 = parent.Derive(new KeyPath("1/1"));


            ExtKey ceoKey = new ExtKey();
            ExtKey accountingKey = ceoKey.Derive(0, hardened: true);
            ExtPubKey ceoPubkey = ceoKey.Neuter();

            //Crash !
            ExtKey ceoKeyRecovered = accountingKey.GetParentExtKey(ceoPubkey);

            Console.WriteLine(ceoKey.ToString(Network.Main));
            Console.WriteLine(ceoKeyRecovered.ToString(Network.Main));

            ceoKey = new ExtKey();
            string accounting = "1'";
            int customerId = 5;
            int paymentId = 50;
            KeyPath path = new KeyPath(accounting + "/" + customerId + "/" + paymentId);
            //Path : "1'/5/50"


            ExtKey paymentKey = ceoKey.Derive(path);

            var hardened = new KeyPath("1/2/3'");
            var nonhardened = new KeyPath("1/2/3");


        }

        private void Code9()
        {
            BitcoinPassphraseCode passphraseCode = new BitcoinPassphraseCode("my secret", Network.Main, null);

            EncryptedKeyResult encryptedKey1 = passphraseCode.GenerateEncryptedSecret();

            Console.WriteLine(encryptedKey1.GeneratedAddress);
            Console.WriteLine(encryptedKey1.EncryptedKey);
            Console.WriteLine(encryptedKey1.ConfirmationCode);

            var confirmationCode = encryptedKey1.ConfirmationCode;
            var generatedAddress = encryptedKey1.GeneratedAddress;
            var encryptedKey = encryptedKey1.EncryptedKey;

            Console.WriteLine(confirmationCode.Check("my secret", generatedAddress));
            BitcoinSecret privateKey = encryptedKey.GetSecret("my secret");
            Console.WriteLine(privateKey.GetAddress() == generatedAddress);
            Console.WriteLine(privateKey);


        }

        private void Code8()
        {
            var key = new Key();
            BitcoinSecret wif = key.GetBitcoinSecret(Network.Main);
            Console.WriteLine(wif);
            BitcoinEncryptedSecret encrypted = wif.Encrypt("secret");
            Console.WriteLine(encrypted);
            wif = encrypted.GetSecret("secret");
            Console.WriteLine(wif);
        }

        private void Code7()
        {
            var address = new BitcoinPubKeyAddress("1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB");
            var msg = "Nicolas Dorier Book Funding Address";
            var sig = "H1jiXPzun3rXi0N9v9R5fAWrfEae9WPmlL5DJBj1eTStSvpKdRR8Io6/uT9tGH/3OnzG6ym5yytuWoA9ahkC3dQ=";
            Console.WriteLine(address.VerifyMessage(msg, sig));

            msg = "Prove me you are 1LUtd66PcpPx64GERqufPygYEWBQR2PUN6";
            sig = paymentSecret.PrivateKey.SignMessage(msg);
            Console.WriteLine(paymentSecret.GetAddress().VerifyMessage(msg, sig));

        }

        private void Code6()
        {
            var blockr = new BlockrTransactionRepository();
            Transaction fundingTransaction = blockr.Get("0b948b0674a3dbd229b2a0b436e0fce8aa84e6de28b088c610d110c2bf54acb4");

            Transaction payment = new Transaction();
            payment.Inputs.Add(new TxIn()
            {
                PrevOut = new OutPoint(fundingTransaction.GetHash(), 1)
            });

            var programmingBlockchain = new BitcoinPubKeyAddress("1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB");
            payment.Outputs.Add(new TxOut()
            {
                Value = Money.Coins(0.004m),
                ScriptPubKey = programmingBlockchain.ScriptPubKey
            });
            payment.Outputs.Add(new TxOut()
            {
                Value = Money.Coins(0.0059m),
                ScriptPubKey = paymentAddress.ScriptPubKey
            });

            //Feedback !
            var message = "Thanks ! :)";
            var bytes = Encoding.UTF8.GetBytes(message);
            payment.Outputs.Add(new TxOut()
            {
                Value = Money.Zero,
                ScriptPubKey = TxNullDataTemplate.Instance.GenerateScriptPubKey(bytes)
            });

            Console.WriteLine(payment);

            payment.Inputs[0].ScriptSig = paymentAddress.ScriptPubKey;
            //also OK :
            //payment.Inputs[0].ScriptSig = fundingTransaction.Outputs[1].ScriptPubKey; 
            payment.Sign(paymentSecret, false);
            Console.WriteLine(payment);

            using (var node = Node.ConnectToLocal(Network.Main)) //Connect to the node
            {
                node.VersionHandshake(); //Say hello
                //Advertize your transaction (send just the hash)
                node.SendMessage(new InvPayload(InventoryType.MSG_TX, payment.GetHash()));
                //Send it
                node.SendMessage(new TxPayload(payment));
                Thread.Sleep(500); //Wait a bit
            }
            return;
        }


        BitcoinSecret paymentSecret;
        BitcoinAddress paymentAddress;
        public Program()
        {
            paymentSecret = new BitcoinSecret("L5W89cAuSXoyzdY1yTyTTX8B3EHDbrVpWyk5T197eoyngvgczbAi");
            paymentAddress = paymentSecret.GetAddress();
        }




        private void Code5()
        {
            var blockr = new BlockrTransactionRepository();
            Transaction transaction = blockr.Get("0b948b0674a3dbd229b2a0b436e0fce8aa84e6de28b088c610d110c2bf54acb4");
            Console.WriteLine(transaction.ToString());
        }

        private static void Code4()
        {
            Key key = new Key();
            BitcoinSecret secret = key.GetBitcoinSecret(Network.Main);
            Console.WriteLine(secret);
        }

        private static void Code3()
        {
            Script scriptPubKey = new Script("OP_DUP OP_HASH160 ff77ae0a6f61fedd8d7ee6dff72d47cb62a06e66 OP_EQUALVERIFY OP_CHECKSIG");
            KeyId hash = (KeyId)scriptPubKey.GetDestination();
            Console.WriteLine("Hash public key : " + hash);
            BitcoinAddress address = new BitcoinPubKeyAddress(hash, Network.Main);
            Console.WriteLine("Address : " + address);
        }

        private static void Code2()
        {
            Script scriptPubKey = new Script("OP_DUP OP_HASH160 ff77ae0a6f61fedd8d7ee6dff72d47cb62a06e66 OP_EQUALVERIFY OP_CHECKSIG");
            BitcoinAddress address = scriptPubKey.GetDestinationAddress(Network.Main);
            Console.WriteLine("Address : " + address);
        }

        private static void Code1()
        {
            Key key = new Key(); //Create the private key
            PubKey pubkey = key.PubKey; //Get the public key
            Console.WriteLine("Public key : " + pubkey);
            KeyId hash = pubkey.Hash;
            Console.WriteLine("Hash public key : " + hash);
            BitcoinAddress address = pubkey.GetAddress(Network.Main); //Get the address on the main network
            //var address = hash.ScriptPubKey;   is also possible
            Console.WriteLine("Address : " + address);
            Script scriptPubKey = address.ScriptPubKey; //Get the scriptPubKey
            Console.WriteLine("Script : " + scriptPubKey);
        }
    }
}
