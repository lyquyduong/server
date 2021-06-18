using System;
using System.Diagnostics;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Bit.Portal.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Bit.Core.Models.Table;

namespace Bit.Portal.Controllers
{
    public class HomeController : Controller
    {
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<HomeController> _logger;
        private readonly EnterprisePortalCurrentContext _enterprisePortalCurrentContext;

        public HomeController(
            SignInManager<User> signInManager,
            ILogger<HomeController> logger,
            EnterprisePortalCurrentContext enterprisePortalCurrentContext)
        {
            _signInManager = signInManager;
            _logger = logger;
            _enterprisePortalCurrentContext = enterprisePortalCurrentContext;
        }

        public IActionResult Index()
        {
            _logger.LogInformation("DebugPortal(4) - HomeController: Index - userIsSignedIn={0}", _signInManager.IsSignedIn(User));
            if(_signInManager.IsSignedIn(User))
            {
                _logger.LogInformation("DebugPortal(5) - HomeController: Index - returning View");
                return View();
            }
            else
            {
                _logger.LogInformation("DebugPortal(6) - HomeController: Index - Returning 404");
                return NotFound();
            }
                _logger.LogInformation("DebugPortal(7) - HomeController: Index - Done");
        }

        [HttpGet("~/alive")]
        [HttpGet("~/now")]
        [AllowAnonymous]
        public DateTime GetAlive()
        {
            return DateTime.UtcNow;
        }

        [Authorize]
        public IActionResult SetSelectedOrganization(Guid id, string returnUrl)
        {
            if (_enterprisePortalCurrentContext.Organizations.Any(o => o.Id == id))
            {
                Response.Cookies.Append("SelectedOrganization", id.ToString(), new CookieOptions { HttpOnly = true });
            }
            if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
