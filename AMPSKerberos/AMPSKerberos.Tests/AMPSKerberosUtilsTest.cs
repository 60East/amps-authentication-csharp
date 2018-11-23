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