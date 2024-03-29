﻿//   Copyright 2021-present Etherna Sagl
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

using IdentityModel;

namespace Etherna.Authentication
{
    public static class EthernaClaimTypes
    {
        public const string ClientId = "client_id";
        public const string EtherAddress = "ether_address";
        public const string EtherPreviousAddresses = "ether_prev_addresses";
        public const string IsWeb3Account = "isWeb3Account";
        public const string Role = JwtClaimTypes.Role;
        public const string UserId = JwtClaimTypes.Subject;
        public const string Username = "preferred_username";
    }
}
