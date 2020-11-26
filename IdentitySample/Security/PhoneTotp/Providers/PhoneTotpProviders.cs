using Microsoft.Extensions.Options;
using OtpNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentitySample.Security.PhoneTotp.Providers
{
    public class PhoneTotpProviders : IPhoneTotpProviders
    {
        private Totp _totp;
        private readonly PhoneTotpOptions _options;
        public PhoneTotpProviders(IOptions<PhoneTotpOptions> options)
        {
            _options = options?.Value ?? new PhoneTotpOptions();
        }

        /// <inheritdoc/>
        public string GenerateTotp(string secretKey)
        {
            CreateTotp(secretKey);

            return _totp.ComputeTotp();
        }

        /// <inheritdoc/>
        public PhoneTotpResult VerifyTotp(string secretKey, string totpCode)
        {
            CreateTotp(secretKey);

            var isTotpCodeValid = _totp.VerifyTotp(totpCode, out _);
            if (isTotpCodeValid)
                return new PhoneTotpResult()
                {
                    Succeeded = true
                };

            return new PhoneTotpResult()
            {
                Succeeded = false,
                ErrorMessage = "کد وارد شده معتبر نیست لطفا کد جدیدی دریافت کنید."
            };
        }

        private void CreateTotp(string secretKey)
        {
            _totp = new Totp(Encoding.UTF8.GetBytes(secretKey), _options.StepInSeconds);
        }
    }
}
