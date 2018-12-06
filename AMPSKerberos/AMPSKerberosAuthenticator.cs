using System;
using AMPS.Client;
using NSspi;
using NSspi.Contexts;
using NSspi.Credentials;

namespace AMPSKerberos
{
    public class AMPSKerberosAuthenticator : AMPS.Client.Authenticator
    {
        private ClientContext ctx;

        public AMPSKerberosAuthenticator(string spn_)
        {
            AMPSKerberosUtils.ValidateSPN(spn_);

            ClientCurrentCredential clientCred = new ClientCurrentCredential("Kerberos");
            
            ctx = new ClientContext(
                clientCred,
                spn_,
                ContextAttrib.MutualAuth |
                ContextAttrib.ReplayDetect |
                ContextAttrib.SequenceDetect |
                ContextAttrib.Connection
            );
        }

        public string authenticate(string username_, string encodedInToken_)
        {
            SecurityStatus clientStatus;
            byte[] inToken = null;
            byte[] outToken = null;
            if (!string.IsNullOrEmpty(encodedInToken_))
            {
                inToken = Convert.FromBase64String(encodedInToken_);
            }

            clientStatus = ctx.Init(inToken, out outToken);

            return (clientStatus == SecurityStatus.OK) ? null : Convert.ToBase64String(outToken);
        }

        public string retry(string username_, string encodedInToken_)
        {
            return authenticate(username_, encodedInToken_);
        }

        public void completed(string username_, string encodedInToken_, Message.Reasons reason_)
        {
            if (reason_ == AMPS.Client.Message.Reasons.AuthDisabled)
            {
                return;
            }

            authenticate(username_, encodedInToken_);
        }
    }
}
