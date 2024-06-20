using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    public class GenerateAesResult : BaseAuthorizationApiResult
    {
        public long EncKeyID { get; set; }

        public string AES_Key { get; set; }

        public string AES_IV { get; set; }

        public string ExpireDate { get; set; }


    }
}
