﻿using System.Collections.Generic;

namespace IdentitySample.ViewModel.ManageUser
{
    public class AddOrRemoveClaimViewModel
    {
        #region Constructor

        public AddOrRemoveClaimViewModel()
        {
            UserClaims = new List<ClaimsViewModel>();
        }

        public AddOrRemoveClaimViewModel(string userId, IList<ClaimsViewModel> userClaims)
        {
            UserId = userId;
            UserClaims = userClaims;
        }

        #endregion Constructor

        public string UserId { get; set; }
        public IList<ClaimsViewModel> UserClaims { get; set; }
    }

    public class ClaimsViewModel
    {
        #region Constructor

        public ClaimsViewModel()
        {
        }

        public ClaimsViewModel(string claimType)
        {
            ClaimType = claimType;
        }

        #endregion Constructor

        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}