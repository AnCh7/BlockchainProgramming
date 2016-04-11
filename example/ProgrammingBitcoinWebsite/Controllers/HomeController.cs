using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using ProgrammingBitcoinFunding.Models;
using QBitNinja.Client;
using QBitNinja.Client.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace ProgrammingBitcoinFunding.Controllers
{
    public class HomeController : Controller
    {
        public ViewResult Index()
        {
            MakersModel makers = GetMakers();
            Trace.TraceInformation("Hello");
            return View(makers);
        }

        public ActionResult Download()
        {
            var o = Trace.Listeners.OfType<TraceListener>().Where(t => t.GetType().Name.Contains("Drive")).First();
            var name = Path.GetFileName(o.GetType().Assembly.Location);
            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = name,

                // always prompt the user for downloading, set to true if you want 
                // the browser to try to show the file inline
                Inline = false,
            };
            Response.AppendHeader("Content-Disposition", cd.ToString());
            return File(System.IO.File.ReadAllBytes(o.GetType().Assembly.Location), "application/octet-stream");
        }

        public static MakersModel GetMakers()
        {
            QBitNinjaClient client = CreateClient();
            var balance = client.GetBalance(new BitcoinPubKeyAddress("1KF8kUVHK42XzgcmJF4Lxz4wcL5WDL97PB")).Result;

            MakersModel makers = new MakersModel();
            var tip = client.GetBlock(new BlockFeature(SpecialFeature.Last), true).Result;
            makers.Height = tip.AdditionalInformation.Height;
            var last = (DateTimeOffset.UtcNow - tip.AdditionalInformation.BlockHeader.BlockTime);
            makers.Time = last.Hours + " h " + last.Minutes + " min " + last.Seconds + " sec ago";

            foreach(var maker in balance.Operations
                   .Where(o => o.Amount >= Money.Coins(0.004m))
                   .Select(o => new
                   {
                       Tx = GetTransaction(o.TransactionId),
                       Op = o
                   })
                   .Where(o => o.Tx != null && !o.Tx.IsCoinbase)
                   .OrderByDescending(o => ExtractWords(o.Tx.Transaction) == null ? 0 : 1)
                   .ThenByDescending(o => o.Op.Amount.Satoshi)
                   .ThenByDescending(o => o.Op.Confirmations)
                   )
            {
                var m = new Maker();
                m.TransactionId = maker.Tx.TransactionId;
                m.TransactionUri = new Uri("http://api.qbit.ninja/transactions/" + m.TransactionId);
                m.Address = maker.Tx.Transaction.Inputs[0].ScriptSig.GetSignerAddress(Network.Main);
                m.AddressUri = new Uri("http://api.qbit.ninja/balances/" + m.Address);
                m.Amount = maker.Op.Amount;
                m.KindWords = ExtractWords(maker.Tx.Transaction);
                if(m.KindWords == null)
                {
                    m.KindWords = "(lazy)";
                }
                m.Position = makers.Makers.Count + 1;
                makers.Makers.Add(m);
            }
            return makers;
        }

        private static string ExtractWords(Transaction transaction)
        {
            try
            {
                return
                    transaction.Outputs
                    .Select(o => TxNullDataTemplate.Instance.ExtractScriptPubKeyParameters(o.ScriptPubKey))
                    .Where(o => o != null && o.Length == 1)
                    .Select(o => Encoding.UTF8.GetString(o[0]))
                    .FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        private static MemoryCache _cache = MemoryCache.Default;
        private static GetTransactionResponse GetTransaction(uint256 txId)
        {
            var result = _cache.Get("tx" + txId) as GetTransactionResponse;
            if(result != null)
                return result;
            result = CreateClient().GetTransaction(txId).Result;
            if(result == null)
                return null;
            _cache.Add("tx" + txId, result, new CacheItemPolicy()
            {
                SlidingExpiration = TimeSpan.FromMinutes(60)
            });
            return result;
        }

        private static QBitNinjaClient CreateClient()
        {
            return new QBitNinjaClient(new Uri("http://api.qbit.ninja/"), Network.Main);
        }

        [Route("mast")]
        public ViewResult MAST()
        {
            string script =
            "OP_HASH160 OP_DUP 8a32aa42900a5f3cdc1c9bf93f12597ca56f9335210d019e12aed94528cacc81 OP_EQUAL \r\n" +
            "OP_IF \r\n" +
                "\t0cbd OP_CLTV \r\n" +
                "\tOP_2DROP \r\n" +
                "\t8a32aa42900a5f3cdc1c9bf93f12597ca56f9335210d019e12aed94528cacc81 \r\n" +
            "OP_ELSE \r\n" +
                "\t8a32aa42900a5f3cdc1c9bf93f12597ca56f9335210d019e12aed94528cacc81 OP_EQUAL \r\n" +
                "\tOP_NOTIF \r\n" +
                    "\t\t0cbd OP_CLTV \r\n" +
                "\tOP_ENDIF \r\n" +
                "\t8a32aa42900a5f3cdc1c9bf93f12597ca56f9335210d019e12aed94528cacc81 \r\n" +
            "OP_ENDIF \r\n" +
            "OP_CHECKSIG";
            return MAST(new MASTModel()
            {
                Script = script
            });
        }
        [Route("redeem")]
        public ViewResult Redeem(string address)
        {
            var result = new BitcoinPubKeyAddress(address);
            return View(new RedeemModel()
            {
                Challenge = CreateChallenge(result)
            });
        }

        private string CreateChallenge(BitcoinAddress address)
        {
            return "Part 1 : Are you really " + address + " ?";
        }

        public ViewResult AboutMe()
        {
            return View();
        }

        [HttpPost]
        [Route("checktx")]
        public ViewResult TransactionCheck(TransactionCheckModel model)
        {
            model = model ?? new TransactionCheckModel();
            QBitNinjaClient client = new QBitNinjaClient("https://segnet.metaco.com/", Network.SegNet);
            if(model.Transaction != null)
            {
                Transaction tx = null;
                try
                {
                    tx = new Transaction(model.Transaction);
                }
                catch(FormatException ex)
                {
                    ModelState.AddModelError("Transaction", "Can't parse transaction (" + ex.Message + ")");
                    return View(model);
                }
                var totalSize = tx.ToBytes().Length;
                var coreSize = tx.WithOptions(TransactionOptions.None).ToBytes().Length;
                model.WitnessSize = totalSize - coreSize;
                model.CoreSize = coreSize;
                model.TransactionCost = coreSize * 4 + model.WitnessSize;
                model.HasWitness = tx.HasWitness;
                if(model.HasWitness)
                {
                    model.EstimatedCostNoWit = (coreSize + model.WitnessSize) * 4;
                    model.Saving = (int)(((decimal)(model.EstimatedCostNoWit - model.TransactionCost) / model.EstimatedCostNoWit) * 100);
                }
                else
                {
                    model.ScriptSigSize = tx.Inputs.Select(i => i.ScriptSig.Length).Sum();
                    model.EstimatedCostWit = (coreSize - model.ScriptSigSize) * 4 + model.ScriptSigSize;
                    model.Saving = (int)(((decimal)(model.TransactionCost - model.EstimatedCostWit) / model.TransactionCost) * 100);
                }
                model.Result = new CheckResult();
                model.Result.Success = true;
                model.Result.Id = tx.GetHash();
                foreach(var input in tx.Inputs.AsIndexedInputs())
                {
                    if(tx.IsCoinBase)
                        break;
                    InputCheckResult inputCheck = new InputCheckResult();
                    inputCheck.PrevOut = input.PrevOut;
                    inputCheck.Witness = input.WitScript;
                    inputCheck.ScriptSig = input.ScriptSig;

                    var previous = client.GetTransaction(input.PrevOut.Hash).Result;
                    model.Result.InputResults.Add(inputCheck);
                    if(previous == null || previous.Transaction.Outputs.Count <= input.PrevOut.N)
                    {
                        model.Result.Success = false;
                        inputCheck.ScriptError = "Previous output not found";
                        ModelState.AddModelError("Transaction", "Previous output not found (" + input.PrevOut + ")");
                        continue;
                    }
                    var output = previous.Transaction.Outputs[input.PrevOut.N];
                    inputCheck.ScriptPubKey = output.ScriptPubKey;
                    inputCheck.Amount = output.Value;
                    ScriptEvaluationContext evaluator = new ScriptEvaluationContext();
                    evaluator.VerifyScript(input.ScriptSig, output.ScriptPubKey, new TransactionChecker(tx, (int)input.Index, output.Value));
                    if(evaluator.Error != ScriptError.OK)
                    {
                        inputCheck.ScriptError = Enum.GetName(typeof(ScriptError), evaluator.Error);
                        model.Result.Success &= false;
                    }

                    var scriptId = PayToScriptHashTemplate.Instance.ExtractScriptPubKeyParameters(inputCheck.ScriptPubKey);
                    if(scriptId != null)
                    {
                        var s = PayToScriptHashTemplate.Instance.ExtractScriptSigParameters(input.ScriptSig, scriptId);
                        inputCheck.P2SHRedeemScript = s == null ? null : s.RedeemScript;
                    }
                    inputCheck.SignatureHash = evaluator.SignedHashes.FirstOrDefault();
                }
            }
            return View(model);
        }

        class Keyset
        {
            public Keyset(string name)
            {
                Name = name;
                Key = GenerateKey(name);
            }

            private Key GenerateKey(string name)
            {
                Rfc2898DeriveBytes derived = new Rfc2898DeriveBytes(name.ToLowerInvariant(), Enumerable.Range(0,8).Select(_=>(byte)0).ToArray(), 1);
                return new Key(derived.GetBytes(32));
            }
            public string Name
            {
                get;
                set;
            }
            public Key Key
            {
                get;
                set;
            }

            internal string GetValue(string element, Script prevScript)
            {
                if(element.Equals("key", StringComparison.InvariantCultureIgnoreCase))
                    return Encoders.Hex.EncodeData(Key.ToBytes());
                if(element.Equals("pubkey", StringComparison.InvariantCultureIgnoreCase))
                    return Encoders.Hex.EncodeData(Key.PubKey.ToBytes());
                if(element.Equals("pubkeyhash", StringComparison.InvariantCultureIgnoreCase))
                    return Encoders.Hex.EncodeData(Key.PubKey.Hash.ToBytes());
                if(element.StartsWith("signature", StringComparison.InvariantCultureIgnoreCase))
                {
                    var split = element.Split(';');
                    if((split.Length != 2 && split.Length != 1) || !split[0].Equals("signature", StringComparison.InvariantCultureIgnoreCase))
                        return null;

                    int index = -1;
                    if(split.Length == 2)
                        if(!int.TryParse(split[1], out index))
                            return null;

                    prevScript = SubScript(index, prevScript);

                    Transaction tx = DummyTransaction();
                    var sig = tx.Inputs.AsIndexedInputs().First().Sign(Key, DummyCoin(prevScript), SigHash.All);
                    return Encoders.Hex.EncodeData(sig.ToBytes());
                }
                return null;
            }

            private Script SubScript(int index, Script prevScript)
            {
                if(index == -1)
                    return prevScript;
                var separatorIndex = -1;
                List<Op> ops = new List<Op>();
                foreach(var op in prevScript.ToOps())
                {
                    if(op.Code == OpcodeType.OP_CODESEPARATOR)
                        separatorIndex++;
                    if(separatorIndex >= index && !(separatorIndex == index && op.Code == OpcodeType.OP_CODESEPARATOR))
                        ops.Add(op);
                }
                return new Script(ops.ToArray());
            }

            public static Coin DummyCoin(Script prevScript)
            {
                return new Coin()
                {
                    TxOut = new TxOut()
                    {
                        ScriptPubKey = prevScript
                    },
                    Outpoint = new OutPoint(),
                    Amount = Money.Zero
                };
            }

            private byte[] Reverse(byte[] p)
            {
                Array.Reverse(p);
                return p;
            }

            public static Transaction DummyTransaction()
            {
                Transaction tx = new Transaction();
                tx.Version = 2;
                tx.LockTime = new LockTime(0);
                tx.Inputs.Add(new TxIn()
                {
                    Sequence = new Sequence(0)
                });
                tx.Outputs.Add(new TxOut());
                return tx;
            }
        }


        Script GetExecutedScript(string scriptTemplate, Script prevScript, Dictionary<string, Keyset> sets)
        {
            StringBuilder executedScript = new StringBuilder();
            int lastToCopy = 0;
            foreach(Match match in Regex.Matches(scriptTemplate, "<([^\\.]*?)\\.([^.]*?)>"))
            {
                var name = match.Groups[1].Value;
                Keyset keyset;
                if(!sets.TryGetValue(name.ToLowerInvariant(), out keyset))
                {
                    keyset = new Keyset(name);
                    sets.Add(name.ToLowerInvariant(), keyset);
                }
                var element = match.Groups[2].Value;
                var replacement = keyset.GetValue(element, prevScript);
                if(replacement == null)
                {
                    throw new Exception("Element " + element + " unrecognized, possible values are pubkey, pubkeyhash ,key, signature");
                }
                var before = scriptTemplate.Substring(lastToCopy, match.Index - lastToCopy);
                executedScript.Append(before);
                executedScript.Append(replacement);
                lastToCopy = match.Index + match.Length;
            }
            executedScript.Append(scriptTemplate.Substring(lastToCopy, scriptTemplate.Length - lastToCopy));
            return new Script(executedScript.ToString());
        }


        [Route("savescript")]
        [HttpPost]
        public ActionResult SaveScript(ScriptCheckModel model)
        {
            SavedScript saved = new SavedScript();
            saved.ScriptPubKey = model.ScriptPubKey;
            saved.ScriptSig = model.ScriptSig;
            repo.InsertScript(saved);
            return RedirectToAction("ScriptCheck", "Home", new
            {
                savedScript = saved.Id.ToString()
            });
        }
        ScriptRepository repo = new ScriptRepository();
        [Route("checkscript")]
        public ActionResult ScriptCheck(string savedScript = null)
        {
            SavedScript script = null;
            Guid id;
            if(!String.IsNullOrEmpty(savedScript) && Guid.TryParse(savedScript, out id))
            {
                try
                {
                    script = repo.GetScript(id);

                }
                catch
                {
                }
            }


            var model = new ScriptCheckModel()
            {
                ScriptPubKey = "OP_DUP OP_HASH160 <Alice.PubkeyHash> OP_EQUALVERIFY OP_CHECKSIG",
                ScriptSig = "<Alice.Signature> <Alice.Pubkey>",
            };
            if(script != null)
            {
                model.SavedScriptLink = GetScriptLink(script.Id);
                model.ScriptPubKey = script.ScriptPubKey;
                model.ScriptSig = script.ScriptSig;
            }
            return ScriptCheck(model);
        }

        private string GetScriptLink(Guid id)
        {
            return this.Url.Action("ScriptCheck", "Home", new
            {
                savedScript = id
            }, this.Request.Url.Scheme);
        }

        [Route("checkscript")]
        [HttpPost]
        public ActionResult ScriptCheck(ScriptCheckModel model)
        {
            if(!string.IsNullOrEmpty(model.Share))
                return SaveScript(model);

            model.ScriptPubKey = model.ScriptPubKey ?? "";
            model.ScriptSig = model.ScriptSig ?? "";
            bool parseProblem = false;

            Dictionary<string, Keyset> sets = new Dictionary<string, Keyset>();
            try
            {
                model.ExecutedScriptPubKey = GetExecutedScript(model.ScriptPubKey, Script.Empty, sets);
            }
            catch(FormatException ex)
            {
                ModelState.AddModelError("ScriptPubKey", "Parsing error");
                parseProblem = true;
            }
            catch(Exception ex)
            {
                ModelState.AddModelError("ScriptPubKey", ex.Message);
                parseProblem = true;
            }

            try
            {
                model.ExecutedScriptSig = GetExecutedScript(model.ScriptSig, model.ExecutedScriptPubKey ?? Script.Empty, sets);
            }
            catch(FormatException ex)
            {
                ModelState.AddModelError("ScriptSig", "Parsing error");
                parseProblem = true;
            }
            catch(Exception ex)
            {
                ModelState.AddModelError("ScriptSig", ex.Message);
                parseProblem = true;
            }

            if(parseProblem)
            {
                return View(model);
            }

            ScriptEvaluationContext ctx = new ScriptEvaluationContext();
            model.Result = new ScriptResultModel();
            var tx = Keyset.DummyTransaction();
            model.Result.Success = ctx.VerifyScript(model.ExecutedScriptSig, model.ExecutedScriptPubKey, tx, 0, Money.Zero);
            model.Result.Error = ctx.Error.ToString();
            model.Result.StackValues = ctx.Stack.Select(b =>
            {
                var hex = Encoders.Hex.EncodeData(b);
                var boolean = CastToBool(b);
                var bignum = Utils.BytesToBigInteger(b);
                return new StackValueModel()
                {
                    Bool = boolean.ToString(),
                    Hex = hex,
                    Number = bignum.ToString()
                };
            }).ToArray();

            model.Result.CheckSigs = ctx.SignedHashes.Select(b =>
            {
                return new CheckSigsModel()
                {
                    SignedHash = b.Hash,
                    ScriptCode = b.ScriptCode,
                    Signature = Encoders.Hex.EncodeData(b.Signature.ToBytes())
                };
            }).ToArray();
            tx.Inputs[0].ScriptSig = model.ExecutedScriptSig;
            model.Transaction = tx.ToHex(); 
            return View(model);
        }


        private BigInteger CastToBigNum(bool v)
        {
            return new BigInteger(v ? 1 : 0);
        }

        private static bool CastToBool(byte[] vch)
        {
            for(uint i = 0; i < vch.Length; i++)
            {
                if(vch[i] != 0)
                {

                    if(i == vch.Length - 1 && vch[i] == 0x80)
                        return false;
                    return true;
                }
            }
            return false;
        }

        [Route("checktx")]
        public ViewResult TransactionCheck(string txid = null)
        {
            uint256 id = null;
            Transaction tx = null;
            if(txid != null && uint256.TryParse(txid, out id))
            {
                QBitNinjaClient client = new QBitNinjaClient("https://segnet.metaco.com/", Network.SegNet);
                var result = client.GetTransaction(id).Result;
                if(result != null)
                    tx = result.Transaction;
            }

            return TransactionCheck(new TransactionCheckModel()
            {
                Transaction = tx == null ? "01000000000101cecd90cd38ac6858c47f2fe9f28145d6e18f9c5abc7ef1a41e2f19e6fe0362580100000000ffffffff0130b48d06000000001976a91405481b7f1d90c5a167a15b00e8af76eb6984ea5988ac0247304402206104c335e4adbb920184957f9f710b09de17d015329fde6807b9d321fd2142db02200b24ad996b4aa4ff103000348b5ad690abfd9fddae546af9e568394ed4a83113012103a65786c1a48d4167aca08cf6eb8eed081e13f45c02dc6000fd8f3bb16242579a00000000" : tx.ToHex()
            });
        }

        [HttpPost]
        [Route("mast")]
        public ViewResult MAST(MASTModel model)
        {
            try
            {
                var script = new Script(Sanitize(model.Script));
                model.DecomposedScripts = new List<DecomposedScript>();
                var subScripts = script.Decompose();
                var hashes = subScripts.Select(s => Hashes.Hash256(s.ToBytes())).ToArray();
                model.MerkleRoot = MerkleNode.GetRoot(hashes).Hash;
                int fullScriptSize = script.ToBytes().Length;
                model.FullScriptSize = fullScriptSize;
                int i = 0;
                foreach(var subScript in subScripts)
                {
                    bool[] matches = new bool[hashes.Length];
                    matches[i] = true;
                    PartialMerkleTree partial = new PartialMerkleTree(hashes, matches);
                    DecomposedScript s = new DecomposedScript();
                    s.Script = subScript.ToString();
                    s.Bytes = Encoders.Hex.EncodeData(subScript.ToBytes());
                    s.Hash = Hashes.Hash256(subScript.ToBytes());
                    s.PartialMerkleTree = Encoders.Hex.EncodeData(partial.ToBytes());
                    model.DecomposedScripts.Add(s);
                    s.Size = subScript.ToBytes().Length + partial.ToBytes().Length;
                    s.Saving = (int)(((decimal)(fullScriptSize - s.Size) / fullScriptSize) * 100m);

                    s.Size160 = (int)(subScript.ToBytes().Length + (decimal)partial.ToBytes().Length * 0.625m);
                    s.Saving160 = (int)(((decimal)(fullScriptSize - s.Size160) / fullScriptSize) * 100m);
                    i++;
                }
            }
            catch(FormatException ex)
            {
                ModelState.AddModelError("Script", "Invalid script (" + ex.Message + ")");
                return View(model);
            }
            return View(model);
        }

        private string Sanitize(string script)
        {
            if(script == null)
                return "";
            return script
                        .Replace("\r\n", " ")
                        .Replace("\t", " ");
        }
        [HttpPost]
        [Route("redeem")]
        public ViewResult Redeem(RedeemModel model)
        {
            var address = new BitcoinPubKeyAddress(model.Address);
            model.Challenge = CreateChallenge(address);
            if(model.Signature == "yes")
            {
                ModelState.AddModelError("Signature", "As if I will believe you... Proove it !");
            }
            try
            {
                if(!address.VerifyMessage(model.Challenge, model.Signature))
                {
                    return Liar(model, address);
                }
            }
            catch
            {
                return Liar(model, address);
            }

            if(!GetMakers().Makers.Any(m => m.Address.Equals(address)))
            {
                model.Message = "You did not solved challenge 1 !";
                return View(model);
            }

            model.Message = "Here it is";
            model.Link = "https://aois.blob.core.windows.net/public/Blockchain Programming in CSharp(PART II).pdf";
            return View(model);
        }

        private ViewResult Liar(RedeemModel model, BitcoinAddress address)
        {
            ModelState.AddModelError("Signature", "Liar ! you are not " + address);
            return View(model);
        }
    }
}
