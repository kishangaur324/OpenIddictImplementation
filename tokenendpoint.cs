[HttpPost("token"), Produces("application/json")]
        public async Task<IActionResult> ExchangeToken()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            var psk = "";
            var globalUser = "";
            Data.ApplicationUser user = null;
            var client = Uow.Clients.GetAll().FirstOrDefault(c => c.ClientId == request.ClientId);
            if (client == null)
                return StatusCode(StatusCodes.Status404NotFound, "Client not found!");

            if (!client.Active)
            {
                return StatusCode(StatusCodes.Status400BadRequest, "Client is inactive.");
            }

            var allowedOrigin = HttpContext.Request.Host.ToString().Contains("localhost") ? "*" : client.AllowedOrigin;
            if (allowedOrigin == null) allowedOrigin = "*";

            if (!HttpContext.Response.Headers.ContainsKey("Access-Control-Allow-Origin"))
                HttpContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            if (request.IsPasswordGrantType())
            {
                using var repo = new AuthRepository(_userManager, _configuration);
                user = await repo.FindUser(request.Username, request.Password);
                var errorMessage = "The username or password is incorrect.";

                if (user == null)
                {
                    return StatusCode(StatusCodes.Status400BadRequest, errorMessage);
                }

                globalUser = $"{user.FirstName} {user.LastName}";
                psk = user.Psk;

                var identity = new ClaimsIdentity(
                   TokenValidationParameters.DefaultAuthenticationType);

                identity.AddClaim(Claims.Subject, user.Id.ToString(), Destinations.AccessToken);
                identity.AddClaim(Claims.Username, user.UserName, Destinations.AccessToken);
                identity.AddClaim(Claims.Name, globalUser, Destinations.AccessToken);

                var claimsPrincipal = new ClaimsPrincipal(identity);
                claimsPrincipal.SetScopes(new string[]
                {
                    Scopes.Roles,
                    Scopes.OfflineAccess,
                    Scopes.Email,
                    Scopes.Profile
                });

                claimsPrincipal.SetRefreshTokenLifetime(TimeSpan.FromMinutes(client.RefreshTokenLifeTime));

                var ticket = new AuthenticationTicket(claimsPrincipal
                    ,
                    new AuthenticationProperties()
                    {
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(2),
                        IssuedUtc = DateTime.UtcNow,
                        IsPersistent = true,
                        AllowRefresh = true
                    },
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            else if (request.IsRefreshTokenGrantType())
            {
                var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                user = await _userManager.GetUserAsync(info.Principal);
                if (user == null)
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "The refresh token is no longer valid.");
                }
                return SignIn(info.Principal, info.Properties, info.Ticket.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant type is not implemented.");
        }
