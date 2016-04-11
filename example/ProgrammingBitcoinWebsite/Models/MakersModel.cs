using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding.Models
{
    public class Maker
    {
        public BitcoinAddress Address
        {
            get;
            set;
        }
        public Uri AddressUri
        {
            get;
            set;
        }
        public string KindWords
        {
            get;
            set;
        }
        public Money Amount
        {
            get;
            set;
        }

        public int Position
        {
            get;
            set;
        }
        public Uri TransactionUri
        {
            get;
            set;
        }
        public uint256 TransactionId
        {
            get;
            set;
        }
    }
    public class MakersModel
    {
        public MakersModel()
        {
            Makers = new List<Maker>();
        }
        public List<Maker> Makers
        {
            get;
            set;
        }

        public int Height
        {
            get;
            set;
        }

        public string Time
        {
            get;
            set;
        }
    }
}
