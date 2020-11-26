using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentitySample.Security.PhoneTotp.Providers
{
    public interface IPhoneTotpProviders
    {
        /// <summary>
        /// Will generate a phone friendly TOTP.
        /// </summary>
        /// <param name="secretKey"> a secret key that should be unique for each user. </param>
        /// <returns> phone friendly TOTP </returns>
        string GenerateTotp(string secretKey);

        /// <summary>
        /// Will validate the TOTP code based on the secret key.
        /// </summary>
        /// <param name="secretKey"> The secret key that used for create TOTP </param>
        /// <param name="totpCode"> The TOTP code </param>
        /// <returns> <see cref="PhoneTotpResult"/> </returns>
        PhoneTotpResult VerifyTotp(string secretKey, string totpCode);
    }
}
