using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    public class BaseResult
    {
        [JsonIgnore]
        public bool IsSuccess
        {
            get
            {
                return RtnCode == 1;
            }
            set
            {
                RtnCode = value ? 1 : 0;
            }
        }

        public virtual int RtnCode { get; set; }

        public virtual string RtnMsg { get; set; }
    }
}
