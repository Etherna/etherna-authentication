//   Copyright 2021-present Etherna Sagl
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

using IdentityModel.Client;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Etherna.Authentication.AspNetCore
{
    internal sealed class DiscoveryDocumentService : IDiscoveryDocumentService
    {
        // Fields.
        private readonly string authority;
        private readonly bool requireHttpsMetadata;
        private DiscoveryDocumentResponse? _discoveryDoc;

        // Constructor.
        public DiscoveryDocumentService(
            string authority,
            bool requireHttpsMetadata = true)
        {
            this.authority = authority;
            this.requireHttpsMetadata = requireHttpsMetadata;
        }

        // Method.
        public async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync()
        {
            if (_discoveryDoc is null)
            {
                using var httpClient = new HttpClient();
                using var discoveryRequest = new DiscoveryDocumentRequest
                {
                    Address = authority,
                    Policy = new DiscoveryPolicy { RequireHttps = requireHttpsMetadata }
                };

                var discoveryDoc = await httpClient.GetDiscoveryDocumentAsync(discoveryRequest).ConfigureAwait(false);
                if (discoveryDoc.IsError)
                    throw discoveryDoc.Exception ?? new InvalidOperationException();

                _discoveryDoc = discoveryDoc;
            }

            return _discoveryDoc;
        }
    }
}
