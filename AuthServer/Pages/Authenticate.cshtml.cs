using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.Pages;

public class Authenticate : PageModel
{
    public string Email { get; set; } = Constants.Email;

    public string Password { get; set; } = Constants.Password;

    [BindProperty]
    public string? ReturnUrl { get; set; }

    public string AuthStatus { get; set; } = "";

    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string email, string password)
    {
        if (email != Constants.Email || password != Constants.Password)
        {
            AuthStatus = "Email or password is invalid";
            return Page();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, email),
        };

        var principal = new ClaimsPrincipal(
            new List<ClaimsIdentity>
            {
                new(claims, CookieAuthenticationDefaults.AuthenticationScheme)
            });

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }

        AuthStatus = "Successfully authenticated";
        return Page();
    }
}