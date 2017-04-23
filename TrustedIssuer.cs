using System;

namespace PeterKressJunior.SAML 
{
    /// <summary>
    /// Stores name and SSL certificate thumbprint 
    /// of a Trusted Issuer for comming SAML Assertions.
    /// </summary>
    internal class TrustedIssuer
    {
        internal string IssuerName { get; }
        internal string CertificateThumbprint { get; }

        internal TrustedIssuer(string issuerName, string certificateThumbprint)
        {
            IssuerName = issuerName;
            CertificateThumbprint = certificateThumbprint;
        }
    }
}