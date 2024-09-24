// Copyright 2021-present Etherna SA
// This file is part of EthernaAuthentication.
// 
// EthernaAuthentication is free software: you can redistribute it and/or modify it under the terms of the
// GNU Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
// 
// EthernaAuthentication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License along with EthernaAuthentication.
// If not, see <https://www.gnu.org/licenses/>.

using IdentityModel.Client;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Etherna.Authentication
{
    public class DiscoveryDocumentService : IDiscoveryDocumentService
    {
        // Fields.
        private readonly string authority;
        private readonly bool requireHttpsMetadata;

        private DiscoveryDocumentResponse? discoveryDoc;

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
            if (discoveryDoc is null)
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

                this.discoveryDoc = discoveryDoc;
            }

            return discoveryDoc;
        }
    }
}
