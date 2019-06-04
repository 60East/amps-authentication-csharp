//////////////////////////////////////////////////////////////////////////\
//
// Copyright (c) 2012-2019 60East Technologies Inc., All Rights Reserved.
//
// This computer software is owned by 60East Technologies Inc. and is
// protected by U.S. copyright laws and other laws and by international
// treaties.  This computer software is furnished by 60East Technologies
// Inc. pursuant to a written license agreement and may be used, copied,
// transmitted, and stored only in accordance with the terms of such
// license agreement and with the inclusion of the above copyright notice.
// This computer software or any other copies thereof may not be provided
// or otherwise made available to any other person.
//
// U.S. Government Restricted Rights.  This computer software: (a) was
// developed at private expense and is in all respects the proprietary
// information of 60East Technologies Inc.; (b) was not developed with
// government funds; (c) is a trade secret of 60East Technologies Inc.
// for all purposes of the Freedom of Information Act; and (d) is a
// commercial item and thus, pursuant to Section 12.212 of the Federal
// Acquisition Regulations (FAR) and DFAR Supplement Section 227.7202,
// Government's use, duplication or disclosure of the computer software
// is subject to the restrictions set forth by 60East Technologies Inc..
//
////////////////////////////////////////////////////////////////////////////

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
