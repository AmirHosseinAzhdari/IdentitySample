﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentitySample.Repositories;
using Microsoft.AspNetCore.Authorization;

namespace IdentitySample.Security.Default
{
    public class ClaimRequirement : IAuthorizationRequirement
    {
        public ClaimRequirement(string claimType, string claimValue)
        {
            ClaimType = claimType;
            ClaimValue = claimValue;
        }

        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
    }
}