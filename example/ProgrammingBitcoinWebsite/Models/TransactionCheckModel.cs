using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding.Models
{
    public class TransactionCheckModel
    {
        public string Transaction
        {
            get;
            set;
        }
        public int CoreSize
        {
            get;
            set;
        }

        public int WitnessSize
        {
            get;
            set;
        }

        public int TransactionCost
        {
            get;
            set;
        }
        public CheckResult Result
        {
            get;
            set;
        }

        public bool HasWitness
        {
            get;
            set;
        }

        public int EstimatedCostNoWit
        {
            get;
            set;
        }
        public int EstimatedCostWit
        {
            get;
            set;
        }

        public int ScriptSigSize
        {
            get;
            set;
        }

        public int Saving
        {
            get;
            set;
        }
    }

    public class InputCheckResult
    {
        public SignedHash SignatureHash
        {
            get;
            set;
        }
        public string ScriptError
        {
            get;
            set;
        }

        public WitScript Witness
        {
            get;
            set;
        }

        public Script ScriptSig
        {
            get;
            set;
        }

        public Script ScriptPubKey
        {
            get;
            set;
        }

        public OutPoint PrevOut
        {
            get;
            set;
        }

        public Script P2SHRedeemScript
        {
            get;
            set;
        }

        public Money Amount
        {
            get;
            set;
        }
    }
    public class CheckResult
    {
        public CheckResult()
        {
            InputResults = new List<InputCheckResult>();
        }
        public bool Success
        {
            get;
            set;
        }

        public List<InputCheckResult> InputResults
        {
            get;
            set;
        }

        public uint256 Id
        {
            get;
            set;
        }
    }
}
