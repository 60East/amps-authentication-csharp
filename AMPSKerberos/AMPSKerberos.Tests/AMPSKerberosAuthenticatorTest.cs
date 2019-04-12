using System;
using NUnit.Framework;
using AMPS.Client;

namespace AMPSKerberos.Tests
{

    [TestFixture]
    public class AMPSKerberosAuthenticatorTest
    {
        string _spn;
        string _uri;

        [TestFixtureSetUp]
        public void Init()
        {
            string amps_host = Environment.GetEnvironmentVariable("AMPS_HOST");
            if (string.IsNullOrEmpty(amps_host))
            {
                Assert.Ignore("Kerberos tests are being skipped. Set the AMPS_HOST environment variable to enable them.");
            }

            string amps_port = Environment.GetEnvironmentVariable("AMPS_PORT");
            if (string.IsNullOrEmpty(amps_port))
            {
                amps_port = "6666";
            }

            string amps_user = Environment.GetEnvironmentVariable("AMPS_USER");
            if (string.IsNullOrEmpty(amps_user))
            {
                amps_user = "60east";
            }

            _spn = string.Format("AMPS/{0}", amps_host);
            _uri = string.Format("tcp://{0}@{1}:{2}/amps/json", amps_user, amps_host, amps_port);
        }


        [TestCase]
        public void TestObtainToken()
        {
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn);
            string token = authenticator.authenticate(null, null);
            Assert.IsNotNull(token);
            Assert.IsTrue(token.StartsWith("YII"));
        }

        [TestCase]
        public void TestPublish()
        {
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn);

            using (Client client = new Client("KerberosTestPublisher"))
            {
                client.connect(_uri);
                client.logon(10000, authenticator);
                client.publish("/topic", @"{ ""foo"" : ""bar"" }");
            }
        }

        [TestCase]
        public void TestMultipleAuthWithFailure()
        {
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn);
            bool error_thrown = false;
            using (Client client = new Client("KerberosTestPublisher"))
            {
                for (int i = 0; i < 10; ++i)
                {
                    if (i % 2 == 0)
                    {
                        client.connect(_uri);
                        client.logon(10000, authenticator);
                        client.close();
                    }
                    else
                    {
                        try
                        {
                            client.connect(_uri);
                            client.logon();
                        }
                        catch (AMPS.Client.Exceptions.AuthenticationException)
                        {
                            client.close();
                            error_thrown = true;
                        }
                    }
                }
            }

            Assert.IsTrue(error_thrown);
        }

        [TestCase]
        public void TestMultipleAuth()
        {
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn);

            using (Client client = new Client("KerberosTestPublisher"))
            {
                for (int i = 0; i < 10; ++i)
                {
                    client.connect(_uri);
                    client.logon(10000, authenticator);
                    client.disconnect();
                }

                client.close();
            }
        }

        [TestCase]
        public void TestUndefinedSPN()
        {
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator("AMPS/foo.com");
            Assert.Throws<NSspi.SSPIException>(() => authenticator.authenticate(null, null));
        }
    }
}
