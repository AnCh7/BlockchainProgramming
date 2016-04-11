using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding.Models
{
    public class MASTModel
    {
        public String Script
        {
            get;
            set;
        }

        public List<DecomposedScript> DecomposedScripts
        {
            get;
            set;
        }

        public uint256 MerkleRoot
        {
            get;
            set;
        }

        public int FullScriptSize
        {
            get;
            set;
        }
    }

    public class DecomposedScript
    {

        public string Script
        {
            get;
            set;
        }

        public uint256 Hash
        {
            get;
            set;
        }

        public string Bytes
        {
            get;
            set;
        }

        public string PartialMerkleTree
        {
            get;
            set;
        }

        public int Size
        {
            get;
            set;
        }

        public decimal Saving
        {
            get;
            set;
        }

        public int Size160
        {
            get;
            set;
        }

        public decimal Saving160
        {
            get;
            set;
        }
    }
}
