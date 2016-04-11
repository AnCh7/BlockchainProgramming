using NBitcoin;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding.Models
{
    public class RedeemModel
    {
        public string Address
        {
            get;
            set;
        }

        
        public string Challenge
        {
            get;
            set;
        }
        [Required(ErrorMessage="what ?")]
        public string Signature
        {
            get;
            set;
        }
        public string Message
        {
            get;
            set;
        }

        public string Link
        {
            get;
            set;
        }        
    }
}
