using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    public class ExchangePucCertRequest : BaseAuthorizationApiRequest
    {
        public string ClientPubCert { get; set; }
    }
}
