using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    public class ExchangePucCertResult : BaseAuthorizationApiResult
    {
        public string ServerPubCert { get; set; }

        public long ServerPubCertID { get; set; }

        public string ExpireDate { get; set; }
    }
}
