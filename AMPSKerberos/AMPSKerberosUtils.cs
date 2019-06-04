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
