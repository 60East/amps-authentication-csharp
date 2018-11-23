using System;
using System.Text.RegularExpressions;
using AMPS.Client.Exceptions;

namespace AMPSKerberos
{
    public class AMPSKerberosUtils
    {
        private static readonly string hostPattern = "(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])";
        private static readonly string realmPattern = "@[\\w\\d]+([\\.\\w\\d]*)?";
        private static readonly string spnPattern = string.Format("^(\\w+/)({0})(:\\d+)?({1})?", hostPattern, realmPattern);
        private static readonly string spnFormat = "<service>/<host>[:<port>][@REALM]";
       
        private static readonly Regex spnRegex = new Regex(spnPattern);

        public static void ValidateSPN(String spn_)
        {
            if (!spnRegex.IsMatch(spn_))
            {
                throw new AuthenticationException(
                    string.Format("The specified SPN {0} does not match the format {1}", spn_, spnFormat));
            }
        }
    }
}
