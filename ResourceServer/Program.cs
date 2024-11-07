using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(o =>
{
    o.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

services.AddEndpointsApiExplorer();
services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri("https://localhost:7001/connect/authorize"),
                TokenUrl = new Uri("https://localhost:7001/connect/token"),
                Scopes = new Dictionary<string, string>
                {
                    { "api1", "resource server scope" }
                }
            },
        }
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth2" }
            },
            Array.Empty<string>()
        }
    });
});

services.AddOpenIddict()
    .AddValidation(o =>
    {
        o.SetIssuer("https://localhost:7001");
        o.AddAudiences("resource_server_1");

        o.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        o.UseSystemNetHttp();

        o.UseAspNetCore();
    });

services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
services.AddAuthorization();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI(o =>
{
    o.OAuthClientId("client");
    o.OAuthClientSecret("client-secret");
});

app.MapGet("/api/me", (HttpContext context) => context.User.Identity)
   .RequireAuthorization();

app.Run();