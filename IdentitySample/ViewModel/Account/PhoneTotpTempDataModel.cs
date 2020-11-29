using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentitySample.ViewModel.Account
{
    public class PhoneTotpTempDataModel
    {
        public string SecretKey { get; set; }
        public string PhoneNumber { get; set; }
        public DateTime ExpireTime { get; set; }
    }
}
