using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace ProgrammingBitcoinFunding.Models
{
    public class ScriptCheckModel
    {
        [AllowHtml]
        public string ScriptSig
        {
            get;
            set;
        }
        public string SavedScriptLink
        {
            get;
            set;
        }

        public string Run
        {
            get;
            set;
        }
        public string Share
        {
            get;
            set;
        }
        [AllowHtml]
        public string ScriptPubKey
        {
            get;
            set;
        }        

        public Script ExecutedScriptSig
        {
            get;
            set;
        }
        public Script ExecutedScriptPubKey
        {
            get;
            set;
        }
        public ScriptResultModel Result
        {
            get;
            set;
        }

        public string Transaction
        {
            get;
            set;
        }
    }

    public class ScriptResultModel
    {

        public bool Success
        {
            get;
            set;
        }

        public string Error
        {
            get;
            set;
        }        

        public StackValueModel[] StackValues
        {
            get;
            set;
        }

        public CheckSigsModel[] CheckSigs
        {
            get;
            set;
        }
    }

    public class StackValueModel
    {
        public string Hex
        {
            get;
            set;
        }
        public string Bool
        {
            get;
            set;
        }
        public string Number
        {
            get;
            set;
        }
    }

    public class CheckSigsModel
    {

        public SigHash SigHash
        {
            get;
            set;
        }

        public Script ScriptCode
        {
            get;
            set;
        }

        public uint256 SignedHash
        {
            get;
            set;
        }

        public string Signature
        {
            get;
            set;
        }
    }
}
