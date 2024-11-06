using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using AuthServer;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services.AddRazorPages();

services.AddEndpointsApiExplorer();
services.AddSwaggerGen();

services.AddCors(o => o.AddDefaultPolicy(p =>
{
    p.WithOrigins("https://localhost:7002")
     .AllowAnyHeader();
}));

services.AddDbContext<AuthDbContext>(o =>
{
    o.UseNpgsql("Host=localhost;Port=5432;Database=local-postgres;User Id=postgres;Password=admin", b =>
    {
        b.MigrationsAssembly(typeof(AuthDbContext).Assembly.FullName);
        b.MigrationsHistoryTable("__EFMigrationsHistory");
    });
    // Thêm các entity của OpenIddict
    o.UseOpenIddict();
});

services.AddOpenIddict()
        .AddCore(o =>
        {
            // Ese EF Core stores and models
            o.UseEntityFrameworkCore()
             .UseDbContext<AuthDbContext>();
        })
        .AddServer(o =>
        {
            // Allow flows
            o.AllowAuthorizationCodeFlow();

            // Signing and encryption credentials
            o.AddDevelopmentEncryptionCertificate()
             .AddDevelopmentSigningCertificate();

            // Enable endpoints.
            o.SetAuthorizationEndpointUris("/connect/authorize")
             .SetTokenEndpointUris("/connect/token")
             .SetLogoutEndpointUris("/connect/logout");

            // Hosted by .NET Core
            o.UseAspNetCore()
             .EnableTokenEndpointPassthrough() // https://localhost:7001/.well-known/openid-configuration
             .EnableAuthorizationEndpointPassthrough()
             .EnableLogoutEndpointPassthrough();
        });

services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(c =>
        {
            c.LoginPath = "/Authenticate";
        });

var app = builder.Build();

app.UseExceptionHandler("/Error");
app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.UseSwagger();
app.UseSwaggerUI();

var scope = app.Services.CreateScope();

// Add scopes
{
    var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
    var apiScope = await scopeManager.FindByNameAsync("api1");
    if (apiScope is null)
    {
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            DisplayName = "Api scope",
            Name = "api1",
            Resources =
            {
                "resource_server_1"
            }
        });
    }
}

{
    // Add clients
    var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await context.Database.EnsureCreatedAsync();
    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    var client = await applicationManager.FindByClientIdAsync("web-client");
    if (client is null)
    {
        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web-client",
            ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = "Swagger client application",
            RedirectUris =
            {
                new Uri("https://localhost:7002/swagger/oauth2-redirect.html")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7002/resources")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Logout,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                $"{OpenIddictConstants.Permissions.Prefixes.Scope}api1"
            }
        });
    }
}

app.MapMethods(
    pattern: "/connect/authorize",
    httpMethods: [HttpMethod.Get.Method, HttpMethod.Post.Method],
    async (HttpContext httpContext,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager) =>
    {
        var request = httpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Lấy các oauth parameter trên query hoặc form
        var excluding = new List<string> { OpenIddictConstants.Parameters.Prompt };
        var parameters = httpContext.Request.HasFormContentType
            ? httpContext.Request.Form
                .Where(v => !excluding.Contains(v.Key))
                .ToDictionary(v => v.Key, v => v.Value)
            : httpContext.Request.Query
                .Where(v => !excluding.Contains(v.Key))
                .ToDictionary(v => v.Key, v => v.Value);
        var redirectUrl = httpContext.Request.PathBase + httpContext.Request.Path + QueryString.Create(parameters);

        // Xác thực bằng cookie
        var result = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!IsAuthenticated())
        {
            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = redirectUrl,
                },
                authenticationSchemes:[CookieAuthenticationDefaults.AuthenticationScheme]);
        }

        // Xử lý application và consent
        var application = await applicationManager
            .FindByClientIdAsync(request.ClientId ?? throw new NullReferenceException("Client id not found"))
                          ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");;
        var consentType = await applicationManager.GetConsentTypeAsync(application);
        if (consentType != OpenIddictConstants.ConsentTypes.Explicit)
        {
            return Results.Forbid(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Only explicit consent clients are supported"
                }));
        }

        if (result.Principal is null) throw new NullReferenceException("Principal is null");

        var consentClaim = result.Principal.GetClaim(Constants.ConsentNaming);
        var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

        if (consentClaim != Constants.GrantAccessValue)
        {
            var returnUrl = HttpUtility.UrlEncode(redirectUrl);
            var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";
            return Results.Redirect(consentRedirectUrl);
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        identity
            .SetClaim(OpenIddictConstants.Claims.Subject, userId)
            .SetClaim(OpenIddictConstants.Claims.Email, userId)
            .SetClaim(OpenIddictConstants.Claims.Name, userId)
            .SetClaims(OpenIddictConstants.Claims.Role, [..new List<string> { "user", "admin" }]);

        identity.SetScopes(request.GetScopes());
        identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

        identity.SetDestinations(GetDestinations);

        return Results.SignIn(
            principal: new ClaimsPrincipal(identity),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );

        bool IsAuthenticated()
        {
            if (!result.Succeeded) return false;

            if (!request.MaxAge.HasValue || result.Properties == null) return true;
            var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);

            var expired = !result.Properties.IssuedUtc.HasValue ||
                          DateTimeOffset.UtcNow - result.Properties.IssuedUtc > maxAgeSeconds;
            return !expired;
        }

        IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch (claim.Type)
            {
                case OpenIddictConstants.Claims.Name:
                    yield return OpenIddictConstants.Destinations.AccessToken;

                    if (claim.Subject?.HasScope(OpenIddictConstants.Permissions.Scopes.Profile) == true)
                        yield return OpenIddictConstants.Destinations.IdentityToken;

                    yield break;

                case OpenIddictConstants.Claims.Email:
                    yield return OpenIddictConstants.Destinations.AccessToken;

                    if (claim.Subject?.HasScope(OpenIddictConstants.Permissions.Scopes.Email) == true)
                        yield return OpenIddictConstants.Destinations.IdentityToken;

                    yield break;

                case OpenIddictConstants.Claims.Role:
                    yield return OpenIddictConstants.Destinations.AccessToken;

                    if (claim.Subject?.HasScope(OpenIddictConstants.Permissions.Scopes.Roles) == true)
                        yield return OpenIddictConstants.Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp":
                    yield break;

                default:
                    yield return OpenIddictConstants.Destinations.AccessToken;
                    yield break;
            }
        }
    });

app.MapPost("/connect/token",
    () =>
    {

    });

app.MapPost("/connect/logout",
    () =>
    {

    });

app.Run();