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
            o.AllowAuthorizationCodeFlow()
             .AllowRefreshTokenFlow();

            // Encryption
            o.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

            // Signing and encryption credentials
            o.AddDevelopmentEncryptionCertificate()
             .AddDevelopmentSigningCertificate()
             .DisableAccessTokenEncryption(); // does not encrypt access token

            // Enable endpoints.
            o.SetAuthorizationEndpointUris("/connect/authorize")
             .SetTokenEndpointUris("/connect/token")
             .SetLogoutEndpointUris("/connect/logout")
             .SetIntrospectionEndpointUris("/.well-known/openid-configuration");

            // Scopes
            o.RegisterScopes(
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles);

            // Token lifetimes
            o.SetAccessTokenLifetime(TimeSpan.FromSeconds(20)); // 20s test refresh token
            o.SetRefreshTokenLifetime(TimeSpan.FromDays(1));


            // Hosted by .NET Core
            o.UseAspNetCore()
             .EnableTokenEndpointPassthrough() // https://localhost:7001/.well-known/openid-configuration
             .EnableAuthorizationEndpointPassthrough()
             .EnableLogoutEndpointPassthrough()
             .DisableTransportSecurityRequirement(); // not require https
        });

services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(c =>
        {
            /*
             * The LoginPath property is used by the handler for the redirection target when handling ChallengeAsync.
             * The current url which is added to the LoginPath as a query string parameter named by the ReturnUrlParameter.
             * Once a request to the LoginPath grants a new SignIn identity,
             * the ReturnUrlParameter value is used to redirect the browser back to the original url.
             */
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

// Add clients
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await context.Database.EnsureCreatedAsync();
    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    var client = await applicationManager.FindByClientIdAsync("client");
    if (client is not null) await applicationManager.DeleteAsync(client);
    await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
    {
        ClientId = "client",
        ClientSecret = "client-secret",
        ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
        DisplayName = "Client application",
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
            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

            OpenIddictConstants.Permissions.ResponseTypes.Code,

            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Scopes.Roles,

            $"{OpenIddictConstants.Permissions.Prefixes.Scope}api1"
        }
    });
}

// Add scopes
using (var scope = app.Services.CreateScope())
{
    var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
    var apiScope = await scopeManager.FindByNameAsync("api1");
    if (apiScope is not null) await scopeManager.DeleteAsync(apiScope);
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

// Main endpoint
app.MapMethods("/connect/authorize", [HttpMethod.Get.Method, HttpMethod.Post.Method],
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

        // Xác thực người dùng theo [cookie scheme]
        var result = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Nếu chưa đăng nhập (cookie chưa có access token token)
        // Nếu có rồi thì skip
        if (!IsAuthenticated(result, request))
        {
            // Chuyển hướng đến login page
            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = redirectUrl,
                },
                authenticationSchemes:[CookieAuthenticationDefaults.AuthenticationScheme]);
        }

        // Tìm consent type từ application (đã được seed)
        var application = await applicationManager
            .FindByClientIdAsync(request.ClientId ?? throw new NullReferenceException("Client id not found"))
                          ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        var consentType = await applicationManager.GetConsentTypeAsync(application);

        // Nếu client không được phép sử dụng loại đồng ý (consentType) "Explicit" thì 401
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

        // Nếu user chưa cấp quyền cho client thì chuyển hướng đến màn Consent
        var consentClaim = result.Principal.GetClaim(Constants.ConsentNaming);
        if (consentClaim != Constants.GrantAccessValue)
        {
            var returnUrl = HttpUtility.UrlEncode(redirectUrl);
            var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";
            return Results.Redirect(consentRedirectUrl);
        }

        // Lấy userId từ claims
        var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

        // Tạo ClaimsIdentity chứa các thông tin xác thực và ủy quyền của người dùng (claims, scopes, resource, dest)
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
        identity.SetClaim(OpenIddictConstants.Claims.Subject, userId)
            .SetClaim(OpenIddictConstants.Claims.Email, userId)
            .SetClaim(OpenIddictConstants.Claims.Name, userId);
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
        identity.SetDestinations(GetDestinations);

        return Results.SignIn(
            principal: new ClaimsPrincipal(identity),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    });

// Exchange authorization code for token (access_token, refresh_token)
app.MapPost("/connect/token",
    async (HttpContext context) =>
    {
        var request = context.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        ClaimsPrincipal claimsPrincipal;

        if (request.IsAuthorizationCodeGrantType())
        {
            // Xác thực người dùng theo [openiddict scheme]
            var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Lấy userId từ claims
            var userId = result.Principal!.GetClaim(OpenIddictConstants.Claims.Subject);

            // Set thông tin để tạo token
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType)
                .SetClaim(OpenIddictConstants.Claims.Subject, userId)
                .SetClaim(OpenIddictConstants.Claims.Email, userId)
                .SetClaim(OpenIddictConstants.Claims.Name, userId)
                .SetDestinations(GetDestinations);

            claimsPrincipal = new ClaimsPrincipal(identity);
        }
        else if (request.IsRefreshTokenGrantType())
        {
            // Xác thực người dùng theo [openiddict scheme]
            var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            //Làm mới claim principal
            claimsPrincipal = result.Principal!;
        }
        else
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        return Results.SignIn(
            principal: claimsPrincipal,
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    });

// Logout
app.MapPost("/connect/logout",
    async (HttpContext context) =>
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Results.SignOut(
            authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    });

app.Run();
return;

bool IsAuthenticated(AuthenticateResult result, OpenIddictRequest request)
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