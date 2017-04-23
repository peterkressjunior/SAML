using System.Security.Claims;

namespace PeterKressJunior.Saml 
{
    /// <summary>
    /// Stores information from Security Claims.
    /// Extracts user attributes from Security Claims.
    /// </summary>
    internal class UserAttributes 
    {
        internal string LoginName { get; }
        internal string FirstName { get; }
        internal string LastName { get; }
        internal string EmailAddress { get; }
        internal string AuthnMethod { get; }
        internal string AuthnInstant { get; }

        internal UserAttributes()
        {
            //just for serialization
        }

        internal UserAttributes(string loginName, string firstName,
                    string lastName, string emailAddress, string authnMethod)
        {
            LoginName = loginName;
            FirstName = firstName;
            LastName = lastName;
            EmailAddress = emailAddress;
            AuthnMethod = authnMethod;
        }

        /// <summary>
        /// Extracts user attributes from Security Claims.
        /// TODO: try LINQ here and decide if code looks better.
        /// </summary>
        internal void ExtractFrom(IEnumerable<Claim> claims)
        {
            foreach (Claim claim in claims)
            {
                switch (claim.Type)
                {
                    case "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod":
                        AuthnMethod = claim.Value;
                        break;
                    case "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant":
                        AuthnInstant = claim.Value;
                        break;
                    case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":
                        LoginName = claim.Value;
                        break;
                    case "FirstName":
                        FirstName = claim.Value;
                        break;
                    case "LastName":
                        LastName = claim.Value;
                        break;
                    case "EmailAddress":
                        EmailAddress = claim.Value;
                        break;
                }
            }
        }
    }
}
