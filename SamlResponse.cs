using System;
using System.Text;
using System.Xml;
using System.IO;
using System.Collection;
using System.Collection.Generic;
using System.Collection.ObjectModel;
using System.Security.Claims;
using System.Security.Cryptograhy;
using System.Security.Cryptograhy.Xml;
using System.Security.Cryptograhy.X509Certificates;
using System.Deployment.Internal.CodeSigning;
using System.IdentityModel.Tokens;
using System.IdentityModel.Selectors;

namespace PeterKressJunior.Saml 
{
    internal class SamlResponse
    {
        private SignedXml _SignedResponse;
        private SignedXml _SignedAssertion;
        private X509Certificate2 _ResponseCertificate;
        private X509Certificate2 _AssertionCertificate;
        
        internal string IssuerName { get; }
        internal string StatusCode { get; }
        internal string AssertionXml { get; }
        internal string Recipient { get; }
        internal List<TrustedIssuer> TrustedIssuers { get; }        
        internal List<Uri> AllowedAudiences { get; }

        internal SamlResponse(string samlResponseXml, bool base64Encoded,
                    string recipient, List<TrustedIssuer> trustedIssuers, 
                    List<Uri> allowedAudiences)
        {
            Recipient = recipient;
            TrustedIssuers = trustedIssuers;
            AllowedAudiences = allowedAudiences;

            if (base64Encoded)
            {
                byte[] decodedResponseXml;
                decodedResponseXml = Convert.FromBase64String(samlResponseXml);
                samlResponseXml = Encoding.UTF8.GetString(decodedResponseXml);
            }

            // SHA-256 support is added here
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), 
                            SecurityAlgorithms.RsaSha256Signature)
            
            LoadResponse(samlResponseXml);
        }

        private void LoadResponse(string samlResponseXml)
        {
            try
            {
                XmlDocument samlResponse = new XmlDocument();
                samlResponse.PreserveWhitespace = true;
                samlResponse.LoadXml(samlResponseXml);

                XmlNamespaceManager namespaceManager = new XmlNamespaceManager(samlResponse.NameTable);
                namespaceManager.AddNamespace("saml2p", Saml2Namespace.Protocol);
                namespaceManager.AddNamespace("ds", Saml2Namespace.DigitalSignature);
                namespaceManager.AddNamespace("saml2", Saml2Namespace.Assertion);

                XmlNode response = samlResponse.SelectSingleNode("saml2p:Response", namespaceManager);
                XmlElement responseSignature = (XmlElement)response.SelectSingleNode("ds:Signature", namespaceManager);
                _SignedResponse = new SignedXml((XmlElement)response);
                _SignedResponse.LoadXml(responseSignature);

                KeyInfo responseKeyInfo = _SignedResponse.KeyInfo;
                IEnumerator responseKeyInfoEnumerator = responseKeyInfo.GetEnumerator();
                _ResponseCertificate = new X509Certificate2();

                while (responseKeyInfoEnumerator.MoveNext())
                {
                    if (responseKeyInfoEnumerator.Current is KeyInfoX509Data)
                    {
                        KeyInfoX509Data x509Data = (KeyInfoX509Data)responseKeyInfoEnumerator.Current;
                        if (x509Data.Certificates.Count >= 1)
                        {
                            X509Certificate certificate = (X509Certificate)x509Data.Certificates[0];
                            _ResponseCertificate = new X509Certificate2(certificate);
                        }
                    }
                }

                XmlNode assertion = response.SelectSingleNode("saml2:Assertion", namespaceManager).Clone();
                AssertionXml = assertion.OuterXml;

                XmlElement assertionSignature = (XmlElement)assertion.SelectSingleNode("ds:Signature", namespaceManager);
                _SignedAssertion = new SignedXml((XmlElement)assertion);
                _SignedAssertion.LoadXml(assertionSignature);

                KeyInfo assertionKeyInfo = _SignedAssertion.KeyInfo;
                IEnumerator assertionKeyInfoEnumerator = assertionKeyInfo.GetEnumerator();
                _AssertionCertificate = new X509Certificate2();

                while (assertionKeyInfoEnumerator.MoveNext())
                {
                    if (assertionKeyInfoEnumerator.Current is KeyInfoX509Data)
                    {
                        KeyInfoX509Data x509Data = (KeyInfoX509Data)assertionKeyInfoEnumerator.Current;
                        if (x509Data.Certificates.Count >= 1)
                        {
                            X509Certificate certificate = (X509Certificate)x509Data.Certificates[0];
                            _AssertionCertificate = new X509Certificate2(certificate);
                        }
                    }
                }

                XmlNode issuer = response.SelectSingleNode("saml2:Issuer", namespaceManager).Clone();
                IssuerName = issuer.InnerText;
                
                XmlNode status = response.SelectSingleNode("smal2p:Status", namespaceManager).Clone();
                XmlNode statusCode = status.SelectSingleNode("saml2p:StatusCode", namespaceManager);
                StatusCode = statusCode.Attributes["Value"].Value;

            }
            catch (Exception exception)
            {
                //TODO: log your exception here
            }
        }

        private bool CheckSignatures()
        {
            return CheckSignature(_SignedAssertion, _AssertionCertificate) 
                && CheckSignature(_SignedResponse, _ResponseCertificate);
        }

        private bool CheckSignature(SignedXml signedXml, X509Certificate2 certificate)
        {
            return signedXml.CheckSignature(certificate, false);
        }

        private ReadOnlyCollection<ClaimsIdentity> ValidateAssertion(string assertionXml)
        {
            ReadOnlyCollection<ClaimsIdentity> claimsIdentities = null;
            Saml2SecurityToken securityToken;
            StringReader reader = new StringReader(assertionXml);
            
            using (XmlReader xmlReader = XmlReader.Create(reader))
            {
                if (!xmlReader.ReadToFollowing("saml2:Assertion"))
                {
                    throw new SecurityTokenValidationException("SAML2 Assertion not found.");                  
                }
                
                FixedSaml2SecurityTokenHandler tokenHandler = new FixedSaml2SecurityTokenHandler(Recipient);
                SecurityTokenHandler[] tokenHandlers = new SecurityTokenHandlers[] { tokenHandler };
                SecurityTokenHandlerCollection handlerCollection = new SecurityTokenHandlerCollection(tokenHandlers);
                ConfigurationBasedIssuerNameRegistry issuerNameRegistry = new ConfigurationBasedIssuerNameRegistry();
                
                foreach (TrustedIssuer issuer in TrustedIssuers)
                {
                    issuerNameRegistry.AddTrustedIssuer(issuer.CertificateThumbprint, issuer.IssuerName);                   
                }
                handlerCollection.Configuration.IssuerNameRegistry = issuerNameRegistry;
                
                AudienceRestriction restriction = new AudienceRestriction(AudienceUriMode.Always);
                
                foreach (Uri allowedAudience in AllowedAudiences)
                {
                    restriction.AllowedAudiencesUris.Add(allowedAudience);
                }
                handlerCollection.Configuration.AudienceRestriction = restriction;
                securityToken = (Saml2SecurityToken)handlerCollection.ReadToken(xmlReader.ReadSubtree());
                claimsIdentities = handlerCollection.ValidateToken(securityToken);
            }
            return claimsIdentities;
        }
        
        internal bool Validate(out UserAttibutes userAttributes)
        {
            userAttributes = new UserAttributes();
            bool isValid = false;
            
            if (CheckSignatures())
            {
                ReadOnlyCollection<ClaimsIdentity> claimsIdentities = ValidateAssertion(AssertionXml);
                
                if (claimsIdentities.Count >= 1)
                {
                    ClaimsIdentity claimsIdentity = claimsIdentities[0];
                    IEnumerable<Claim> claims = claimsIdentity.Claims;
                    userAttributes.ExtractFrom(claims);
                    valid = claimsIdentity.IsAuthenticated;
                }
            }
            return isValid;
        }


        //TODO verify response
    }
}
