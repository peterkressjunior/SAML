using System.IdentityModel.Tokens;

namespace PeterKressJunior.Saml
{
    /// <summary>
    /// If the Identity Provider sends the 'Recipient' within the Saml2 Response message,
    /// .NET will throw an exception - here we fixed it by over writting of one method 
    /// and checking the Recipient our self and removing it afterwards befor base class 
    /// is going to check the rest.
    /// </summary>
    internal FixedSaml2SecurityTokenHandler 
        : Saml2SecurityTokenHandler
    {
        private string _TrustedRecipient;
        
        internal FixedSaml2SecurityTokenHandler(string trustedRecipient)
            :base
        {
            _TrustedRecipient = trustedRecipient; 
        }
        
        /// <summary>
        /// </summary>
        protected override void ValidateConfirmationData(Saml2SubjectConfirmationData confirmationData)
        {
            if (confirmationData.Recipient != null)
            {
                if (!confirmationData.Recipient.Equals(trustedRecipient))
                {
                    throw new SecurityTokenValidationException("ID4157A: " 
                        + "ConfirmationData Recipient does not match with registred recipient.");
                }
                confirmationData.Recipient = null;
            }
            base.ValidationConfirmationData(confirmationData);
        }
    }
}
