using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    public class BaseAuthorizationApiResult
    {
        public string Timestamp
        {
            get
            {
                return DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss");
            }
        }
    }
}
