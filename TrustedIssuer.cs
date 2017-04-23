namespace PeterKressJunior.Saml  
{
    /// <summary>
    /// Stores name and SSL certificate thumbprint 
    /// of a Trusted Issuer for comming SAML2 Assertions.
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
