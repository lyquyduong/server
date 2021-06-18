using System.Threading.Tasks;
using Bit.Portal.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Bit.Portal.Controllers
{
    public class AuthController : Controller
    {
        private readonly EnterprisePortalTokenSignInManager _signInManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            ILogger<AuthController> logger,
            EnterprisePortalTokenSignInManager signInManager)
        {
            _logger = logger;
            _signInManager = signInManager;
        }

        [HttpGet("~/login")]
        public async Task<IActionResult> Index(string userId, string token, string organizationId, string returnUrl)
        {
            var result = await _signInManager.TokenSignInAsync(userId, token, false);
            if (!result.Succeeded)
            {
                return RedirectToAction("Index", "Home", new
                {
                    error = 2
                });
            }

            if (!string.IsNullOrWhiteSpace(organizationId))
            {
                Response.Cookies.Append("SelectedOrganization", organizationId, new CookieOptions { HttpOnly = true });
            }

            _logger.LogInformation("DebugPortal(1) - AuthController: returnUrl={0}", returnUrl);
            if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                
                _logger.LogInformation("DebugPortal(2) - AuthController: local redirect - returnUrl={0}", returnUrl);
                return Redirect(returnUrl);
            }

            _logger.LogInformation("DebugPortal(3) - AuthController: home redirect");
            return RedirectToAction("Index", "Home");
        }

        [HttpPost("~/logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("LoggedOut");
        }

        [HttpGet("~/logged-out")]
        public IActionResult LoggedOut()
        {
            return View();
        }

        [HttpGet("~/access-denied")]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
