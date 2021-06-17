using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Bit.Core.Models.Table;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Bit.Portal.Utilities
{
    public class EnterprisePortalTokenSignInManager : SignInManager<User>
    {
        public const string TokenSignInPurpose = "EnterprisePortalTokenSignIn";
        
        private readonly IDataProtector _dataProtector;

        public EnterprisePortalTokenSignInManager(
            UserManager<User> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<User> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<User>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<User> confirmation,
            IDataProtectionProvider dataProtectionProvider)
            : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
            _dataProtector = dataProtectionProvider
                .CreateProtector("DataProtectorTokenProvider")
                .CreateProtector(TokenSignInPurpose);
        }

        public async Task<SignInResult> TokenSignInAsync(User user, string token, bool isPersistent)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var attempt = await CheckTokenSignInAsync(user, token);
            return attempt.Succeeded ?
                await SignInOrTwoFactorAsync(user, isPersistent, bypassTwoFactor: true) : attempt;
        }

        public async Task<SignInResult> TokenSignInAsync(string userId, string token, bool isPersistent)
        {
            var user = await UserManager.FindByIdAsync(userId);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            return await TokenSignInAsync(user, token, isPersistent);
        }

        public virtual async Task<SignInResult> CheckTokenSignInAsync(User user, string token)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            var userId = await UserManager.GetUserIdAsync(user);
            
            try
            {
                Logger.LogInformation("CheckTokenSignInAsync(1): user='{userId}', token='{token}'", userId, token);
                var unprotectedData = _dataProtector.Unprotect(Convert.FromBase64String(token));
                var unprotectedToken = Encoding.UTF8.GetString(unprotectedData);
                Logger.LogInformation("CheckTokenSignInAsync(2): token='{unprotectedToken}'", unprotectedToken);
                var ms = new MemoryStream(unprotectedData);
                using (var reader = ms.CreateReader())
                {
                    var creationTime = reader.ReadDateTimeOffset();
                    Logger.LogInformation("CheckTokenSignInAsync(3): creationTime='{creationTime}'", creationTime);

                    var expirationTime = creationTime + TimeSpan.FromDays(1);
                    Logger.LogInformation("CheckTokenSignInAsync(4): expirationTime='{expirationTime}'", expirationTime);

                    var uid = reader.ReadString();
                    Logger.LogInformation("CheckTokenSignInAsync(5): userId='{uid}'", uid);

                    var purp = reader.ReadString();
                    Logger.LogInformation("CheckTokenSignInAsync(6): purpose='{purp}'", purp);

                    var stamp = reader.ReadString();
                    if (reader.PeekChar() != -1)
                    {
                        Logger.LogInformation("CheckTokenSignInAsync(7): error='Unexpected end of stream - security stamp'");
                    }
                    else
                    {
                        Logger.LogInformation("CheckTokenSignInAsync(7): securityStamp='{stamp}', actualStamp='{SecurityStamp}'", stamp, await UserManager.GetSecurityStampAsync(user));
                    }
                }
                Logger.LogInformation("CheckTokenSignInAsync(8): token='{token}', user='{userId}', unprotectedToken='{unprotectedToken}'",
                    token, userId, unprotectedToken);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "CheckTokenSignInAsync(9): token='{token}', user='{userId}', error='{Message}'", token, userId, ex.Message);
            }

            if (await UserManager.VerifyUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider,
                TokenSignInPurpose, token))
            {
                return SignInResult.Success;
            }

            Logger.LogWarning(2, "User {userId} failed to provide the correct enterprise portal token.",
                await UserManager.GetUserIdAsync(user));
            return SignInResult.Failed;
        }
    }

    /// <summary>
    /// Utility extensions to streams
    /// </summary>
    internal static class StreamExtensions
    {
        internal static readonly Encoding DefaultEncoding = new UTF8Encoding(false, true);

        public static BinaryReader CreateReader(this Stream stream)
        {
            return new BinaryReader(stream, DefaultEncoding, true);
        }

        public static DateTimeOffset ReadDateTimeOffset(this BinaryReader reader)
        {
            return new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
        }
    }
}
