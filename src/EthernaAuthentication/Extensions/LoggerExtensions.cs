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

using Duende.IdentityModel.Client;
using Microsoft.Extensions.Logging;
using System;

namespace Etherna.Authentication.Extensions
{
    /*
     * Always group similar log delegates by type, always use incremental event ids.
     * Last event id is: 0
     */
    internal static class LoggerExtensions
    {
        // Fields.
        //*** WARNING LOGS ***
        private static readonly Action<ILogger, ResponseErrorType, string?, Exception> _userInfoRequestFailed =
            LoggerMessage.Define<ResponseErrorType, string?>(
                LogLevel.Warning,
                new EventId(0, nameof(UserInfoRequestFailed)),
                "Userinfo request failed with an error of type {ErrorType}: {Error}. No user claims are taken from the endpoint");

        // Methods.
        public static void UserInfoRequestFailed(this ILogger logger, ResponseErrorType errorType, string? error, Exception? exception) =>
            _userInfoRequestFailed(logger, errorType, error, exception!);
    }
}
