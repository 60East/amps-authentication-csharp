\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
\\
\\ Copyright (c) 2012-2019 60East Technologies Inc., All Rights Reserved.
\\
\\ This computer software is owned by 60East Technologies Inc. and is
\\ protected by U.S. copyright laws and other laws and by international
\\ treaties.  This computer software is furnished by 60East Technologies
\\ Inc. pursuant to a written license agreement and may be used, copied,
\\ transmitted, and stored only in accordance with the terms of such
\\ license agreement and with the inclusion of the above copyright notice.
\\ This computer software or any other copies thereof may not be provided
\\ or otherwise made available to any other person.
\\
\\ U.S. Government Restricted Rights.  This computer software: (a) was
\\ developed at private expense and is in all respects the proprietary
\\ information of 60East Technologies Inc.; (b) was not developed with
\\ government funds; (c) is a trade secret of 60East Technologies Inc.
\\ for all purposes of the Freedom of Information Act; and (d) is a
\\ commercial item and thus, pursuant to Section 12.212 of the Federal
\\ Acquisition Regulations (FAR) and DFAR Supplement Section 227.7202,
\\ Government's use, duplication or disclosure of the computer software
\\ is subject to the restrictions set forth by 60East Technologies Inc..
\\
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

using System;
using System.Collections;
using NUnit.Framework;
using AMPS.Client.Exceptions;

namespace AMPSKerberos.Tests
{
    [TestFixture]
    public class AMPSKerberosUtilsTest
    {
        ArrayList _validSPNs;
        ArrayList _invalidSPNs;

        [TestFixtureSetUp]
        public void Init()
        {
            _validSPNs = new ArrayList
            {
                 "AMPS/localhost",
                "AMPS/localhost:1234",
                "AMPS/localhost.localdomain",
                "AMPS/localhost.localdomain:1234",
                "AMPS/ac-1234.localhost.com",
                "AMPS/ac-1234.localhost.com:1234",
                "AMPS/localhost@SOMEREALM",
                "AMPS/localhost@SOMEREALM.COM",
                "AMPS/localhost@SOME.REALM.COM",
                "AMPS/localhost:1234@SOMEREALM",
                "AMPS/localhost:1234@SOMEREALM.COM",
                "AMPS/localhost:1234@SOME.REALM.COM",
                "AMPS/localhost.localdomain@SOMEREALM",
                "AMPS/localhost.localdomain@SOMEREALM.COM",
                "AMPS/localhost.localdomain@SOME.REALM.COM",
                "AMPS/localhost.localdomain:1234@SOMEREALM",
                "AMPS/localhost.localdomain:1234@SOMEREALM.COM",
                "AMPS/localhost.localdomain:1234@SOME.REALM.COM"
            };

            _invalidSPNs = new ArrayList
            {
                "FOO",
                "localhost.localdomain",
                "AMPS@localhost",
                "AMPS@localhost.localdomain",
                "AMPS@localhost.localdomain",
                "AMPS@localhost.localdomain/FOO"
            };
        }

        [TestCase]
        public void TestValidateSPN()
        {
            foreach (String validSPN in _validSPNs)
            {
                AMPSKerberosUtils.ValidateSPN(validSPN);
            }
        }

        [TestCase]
        public void TestInvalidSPNs()
        {
            foreach (String invalidSPN in _invalidSPNs)
            {
                Assert.Throws<AuthenticationException>(() => AMPSKerberosUtils.ValidateSPN(invalidSPN));
            }
        }
    }
}
