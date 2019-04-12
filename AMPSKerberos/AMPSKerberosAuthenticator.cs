using System;
using AMPS.Client;
using NSspi;
using NSspi.Contexts;
using NSspi.Credentials;

namespace AMPSKerberos
{
    public class AMPSKerberosAuthenticator : AMPS.Client.Authenticator
    {
        private ClientContext _ctx;
        private string _spn;

        public AMPSKerberosAuthenticator(string spn_)
        {
            AMPSKerberosUtils.ValidateSPN(spn_);
            _spn = spn_;
        }

        private void init()
        {
            ClientCurrentCredential clientCred = new ClientCurrentCredential("Kerberos");

            _ctx = new ClientContext(
                clientCred,
                _spn,
                ContextAttrib.MutualAuth |
                ContextAttrib.ReplayDetect |
                ContextAttrib.SequenceDetect |
                ContextAttrib.Connection
            );
        }

        public string _authenticate(string username_, string encodedInToken_, bool completing_)
        {
            if (!completing_)
            {
                init();
            }
            SecurityStatus clientStatus;
            byte[] inToken = null;
            byte[] outToken = null;
            if (!string.IsNullOrEmpty(encodedInToken_))
            {
                inToken = Convert.FromBase64String(encodedInToken_);
            }

            clientStatus = _ctx.Init(inToken, out outToken);

            return (clientStatus == SecurityStatus.OK) ? null : Convert.ToBase64String(outToken);
        }

        public string authenticate(string username_, string encodedInToken_)
        {
            return _authenticate(username_, encodedInToken_, false);
        }

        public string retry(string username_, string encodedInToken_)
        {
            return authenticate(username_, encodedInToken_);
        }

        public void completed(string username_, string encodedInToken_, Message.Reasons reason_)
        {
            if (reason_ == AMPS.Client.Message.Reasons.AuthDisabled)
            {
                dispose();
                return;
            }

            _authenticate(username_, encodedInToken_, true);
            dispose();
        }

        private void dispose()
        {
            _ctx.Dispose();
            _ctx = null;
        }
    }
}
