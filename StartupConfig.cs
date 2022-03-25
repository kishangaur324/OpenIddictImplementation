var redisDb = ConnectionMultiplexer.Connect(redisConfig).GetDatabase();
services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                        .UseDbContext<IAFConsultingDbContext>()
                        .ReplaceDefaultEntities<Clients, CustomAuthorization, CustomScope, CustomToken, string>();
                })
                .AddServer(options =>
                {
                    options.SetTokenEndpointUris("/token");
                    options.SetIntrospectionEndpointUris("/introspect");

                    options.AllowPasswordFlow();
                    options.AllowRefreshTokenFlow();
                    options.AcceptAnonymousClients();
                    options.IgnoreGrantTypePermissions();
                    options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder => builder.UseSingletonHandler<CustomProcessSignInContext>());
                    
                    options.UseReferenceAccessTokens();
                    options.UseReferenceRefreshTokens();
                    options.DisableScopeValidation();
                    options.DisableSlidingRefreshTokenExpiration();

                    options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email,
                                                OpenIddictConstants.Permissions.Scopes.Profile,
                                                OpenIddictConstants.Permissions.Scopes.Roles,
                                                OpenIddictConstants.Scopes.OfflineAccess
                                                );

                    options.SetAccessTokenLifetime(TimeSpan.FromDays(2));
                    options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));
                    
                    options.AddEncryptionCertificate(new X509Certificate2(GetCertificate(encryptionCert, redisDb, logger)))
                           .AddSigningCertificate(new X509Certificate2(GetCertificate(signingCert, redisDb, logger)));
                    
                    options.UseAspNetCore().EnableTokenEndpointPassthrough().DisableTransportSecurityRequirement();
                })
                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = OpenIddictConstants.Schemes.Bearer;
                options.DefaultChallengeScheme = OpenIddictConstants.Schemes.Bearer;
            });

            services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();
            });
