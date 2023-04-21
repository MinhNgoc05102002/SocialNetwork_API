using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SocialNetwork.Models;
using SocialNetwork.Models.Authentication;
using SocialNetwork.ViewModels;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json.Serialization;
using IHostingEnvironment = Microsoft.AspNetCore.Hosting.IHostingEnvironment;

namespace SocialNetwork.Controllers
{
    public class AccountController : Controller
    {
        private IHostingEnvironment _env;
        SocialNetworkDbContext db = new SocialNetworkDbContext();
        private readonly IConfiguration _configuration;
        public AccountController(IHostingEnvironment _enviroment, IConfiguration configuration)
        {
            _configuration = configuration;
            _env = _enviroment;
        }

        public IActionResult Index()
        {
            return View();
        }

        // =================== Login ===================
        [HttpGet]
        public IActionResult Login()
        {
            if (HttpContext.Session.GetInt32("accountId") == null)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        [HttpPost]
        public IActionResult Login(string email, string password)
        {
            if (HttpContext.Session.GetInt32("accountId") == null)
            {
                var account = db.Accounts.SingleOrDefault(x => x.Email == email && x.Password == password);
                if (account != null)
                {
                    if(account.IsBanned == true)
                    {
                        ModelState.AddModelError("Email", "Your account is banned!");
                        return View();
                    }
                    HttpContext.Session.SetInt32("accountId", account.AccountId);
                    CurrentAccount.initSession(account.AccountId);
                    return RedirectToAction("Index", "Home");
                }
                ModelState.AddModelError("Email", "Invalid email or password");
                return View();
            }
            return RedirectToAction("Index", "Home");
        }

        // =================== Logout ===================
        public IActionResult Logout()
        {
            // xử lý action logout sau đó chuyển về view login 
            HttpContext.Session.Clear();
            HttpContext.Session.Remove("accountId");
            return RedirectToAction("Login", "Account");
        }

        // =================== Register ===================
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(Account account)
        {
            if (db.Accounts.FirstOrDefault(x => x.Email == account.Email) != null)
            {
                ModelState.AddModelError("Email", "Email has already been taken.");
                return View(account);
            }
            if (ModelState.IsValid)
            {
                account.Avatar = "images/avatars/default.jpg";
                db.Accounts.Add(account);
                db.SaveChanges();
                return RedirectToAction("", "");
            }
            return View();
        }

        // =================== Profile ===================
        [Authentication]
        public IActionResult Profile(int? accountId)
        {
            
            int maxAccountId = db.Accounts.Max(x => x.AccountId);
            // Xử lí trường hợp accountId bị null hoặc < 1 hoặc > maxAccountId
            int currentAccountId = CurrentAccount.account.AccountId;
            if (accountId == null || accountId < 1 || accountId > maxAccountId)
            {
                accountId = currentAccountId;
            }
            // Lấy thông tin của tài khoản từ accountId
            var account = db.Accounts.SingleOrDefault(x => x.AccountId == accountId);

            // Kiểm tra xem tài khoản này có bị block không ?
            bool blocked = db.Relationships
                           .SingleOrDefault(x => x.SourceAccountId == currentAccountId 
                                              && x.TargetAccountId == accountId
                                              && x.TypeId == 3) != null;
            if (blocked)
            {
                return RedirectToAction("Index", "Home");
            }
            
            // Đếm số lượng post của account này
            int postCount = db.Posts.Count(x => x.AccountId == accountId && x.IsDeleted == false);
            ViewBag.PostCount = postCount;

            // Lấy danh sách các post detail của tài khoản
            var lstPost = db.Posts.Where(x => x.AccountId == accountId && x.IsDeleted == false).OrderByDescending(x => x.CreateAt).ToList();
            List<PostDetailViewModel> lstPostDetail = new List<PostDetailViewModel>();
            foreach (var item in lstPost)
            {
                lstPostDetail.Add(new PostDetailViewModel(item));
            }
            ViewBag.ListPostDetail = lstPostDetail;

            // Kiểm tra có đang theo dõi tài khoản này hay không
            bool following = db.Relationships
                               .SingleOrDefault(x => x.SourceAccountId == currentAccountId
                                              && x.TargetAccountId == accountId
                                              && x.TypeId == 2) != null;
            ViewBag.Following = following;

            // Kiểm tra xem đã gửi Request Follow chưa
            bool requested = db.Relationships
                               .SingleOrDefault(x => x.SourceAccountId == currentAccountId
                                              && x.TargetAccountId == accountId
                                              && x.TypeId == 1) != null;
            ViewBag.Requested = requested;
            return View(account);
        }

        // =================== Setting ===================
        [Authentication]
        public IActionResult Setting()
        {
            var account = db.Accounts.SingleOrDefault(x => x.Email == CurrentAccount.account.Email);
            return View(account);
        }

        [HttpPost]
        [Authentication]
        public IActionResult setting(Account model, string accountType)
        {
            var account = db.Accounts.SingleOrDefault(x => x.Email == CurrentAccount.account.Email);
            account.FullName = model.FullName;
            account.AboutMe = model.AboutMe;
            account.Location = model.Location;
            account.Phone = model.Phone;
            if (accountType == "public")
            {
                account.AccountType = "Public";
            }
            else
            {
                account.AccountType = "Private";
            }
            db.SaveChanges();
            CurrentAccount.account.FullName = account.FullName;
            CurrentAccount.update();
            return View(account);
        }

        // =================== Avatar ===================
        [HttpPost]
        public IActionResult UploadAvatar(IFormFile image)
        {
            while (image == null)
            {
                System.Threading.Thread.Sleep(100);
            }
            var account = db.Accounts.SingleOrDefault(x => x.Email == CurrentAccount.account.Email);
            var serverMapPath = Path.Combine(_env.WebRootPath, "images/avatars/" + CurrentAccount.account.AccountId);
            var serverMapPathFile = Path.Combine(serverMapPath, image.FileName);
            Directory.CreateDirectory(serverMapPath);
            var files = Directory.GetFiles(serverMapPath);
            foreach (var file in files)
            {
                System.IO.File.Delete(file);
            }
            using (var stream = new FileStream(serverMapPathFile, FileMode.Create))
            {
                image.CopyTo(stream);
            }
            var filepath = "/images/avatars/" + CurrentAccount.account.AccountId + "/" + image.FileName;
            account.Avatar = filepath;
            CurrentAccount.account.Avatar = account.Avatar;
            db.SaveChanges();

            return RedirectToAction("Profile", "Account");
        }

        [HttpPost]
        public IActionResult RemoveAvatar()
        {
            var account = db.Accounts.SingleOrDefault(x => x.Email == CurrentAccount.account.Email);
            account.Avatar = "/images/avatars/default.jpg";
            CurrentAccount.account.Avatar = account.Avatar;
            db.SaveChanges();
            return RedirectToAction("Profile", "Account");
        }

        [Authentication]
        public IActionResult FollowRequest()
        {
            var lstIdRequest = db.Relationships
                .Where(x => x.TargetAccountId == CurrentAccount.account.AccountId && x.TypeId == 1)
                .Select(x => x.SourceAccountId)
                .ToList();
            var lstRequest = db.Accounts.Where(x => lstIdRequest.Contains(x.AccountId)).ToList();
            return View(lstRequest);
        }

        [Authentication]
        public IActionResult BlockedList()
        {
            var lstIdBlocked = db.Relationships
                .Where(x => x.SourceAccountId == CurrentAccount.account.AccountId && x.TypeId == 3)
                .Select(x => x.TargetAccountId)
                .ToList();
            var lstBlocked = db.Accounts.Where(x => lstIdBlocked.Contains(x.AccountId)).ToList();
            return View(lstBlocked);
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult FacebookLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("CallbackLoginFb"),
                Items =
                {
                    { "scheme",  FacebookDefaults.AuthenticationScheme }
                }
            };

            return Challenge(properties, "Facebook");
        }

        [HttpGet]
        public async Task<IActionResult> CallbackLoginFb()
        {
            var result = await HttpContext.AuthenticateAsync(FacebookDefaults.AuthenticationScheme);
            var accessToken = result.Properties.GetTokenValue("access_token");
            var fbUserId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var fbUserName = result.Principal.FindFirstValue(ClaimTypes.Name);
            var fbUserEmail = result.Principal.FindFirstValue(ClaimTypes.Email);

            var client = new HttpClient();
            var response = await client.GetAsync($"https://graph.facebook.com/v11.0/{fbUserId}?fields=id,name,email&access_token={accessToken}");
            var content = await response.Content.ReadAsStringAsync();
            var user = JsonConvert.DeserializeObject<fbAccount>(content);

            var responseImg = await client.GetAsync($"https://graph.facebook.com/v11.0/{fbUserId}/picture?type=large&redirect=false&access_token={accessToken}");
            var img = await responseImg.Content.ReadAsStringAsync();
            var pictureData = JsonConvert.DeserializeObject<FacebookPicture>(img);

            var userExists = db.Accounts.SingleOrDefault(x => x.Email == user.Email);

            if (userExists != null)
            {
                // email này đã dki tài khoản rồi thì cho đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", userExists.AccountId);
                CurrentAccount.initSession(userExists.AccountId);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                const string defaultPassword = "default123";

                // tạo user mới và add vào db 
                var newUser = new Account
                {
                    // Avatar = GetAvatarLink(external),
                    Email = user.Email,
                    DisplayName = user.Email.Split("@")[0],
                    FullName = user.Name,
                    Password = defaultPassword,
                    Avatar = pictureData.Data.Url
                };
                db.Accounts.Add(newUser);
                db.SaveChanges();

                // đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", newUser.AccountId);
                CurrentAccount.initSession(newUser.AccountId);
                return RedirectToAction("Index", "Home");

            }
        }

        [HttpPost]
        public IActionResult GoogleLogin()
        {
            //string redirectUri = Url.Action(nameof(GoogleResponse), "Account", null, Request.Scheme);
            //string clientId = _configuration["Google:AppId"];
            //string clientSecret = _configuration["Google:AppSecret"];

            //// Step 1: Redirect the user to Google's OAuth 2.0 server to request access to the user's Google account.
            //string authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={clientId}&redirect_uri={redirectUri}&scope=email%20profile";
            //return Redirect(authUrl);


            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("CallbackLoginGoogle"),
                Items =
                {
                    { "scheme", GoogleDefaults.AuthenticationScheme  }
                }
            };

            return Challenge(properties, "Google");
        }

        public async Task<IActionResult> GoogleResponse(string code)
        {
            string redirectUri = Url.Action(nameof(GoogleResponse), "Account", null, Request.Scheme);
            string clientId = _configuration["Google:AppId"];
            string clientSecret = _configuration["Google:AppSecret"];

            // Step 2: Exchange authorization code for access token.
            using (HttpClient httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri("https://oauth2.googleapis.com/token");

                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                });

                HttpResponseMessage response = await httpClient.PostAsync("", content);
                string responseString = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    JObject tokenResponse = JObject.Parse(responseString);

                    // Step 3: Get user information using the access token.
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (string)tokenResponse["access_token"]);
                    HttpResponseMessage userInfoResponse = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v3/userinfo");
                    string userInfoResponseString = await userInfoResponse.Content.ReadAsStringAsync();

                    if (userInfoResponse.IsSuccessStatusCode)
                    {
                        JObject userInfo = JObject.Parse(userInfoResponseString);

                        // Save user information to session.
                        HttpContext.Session.SetString("UserId", (string)userInfo["sub"]);
                        HttpContext.Session.SetString("UserName", (string)userInfo["name"]);
                        HttpContext.Session.SetString("UserEmail", (string)userInfo["email"]);

                        return RedirectToAction("Index", "Home");
                    }
                }
            }

            // If the code above fails, return to the login page.
            return RedirectToAction("Login");
        }

        [HttpGet]
        public async Task<IActionResult> CallbackLoginGoogle()
        {
            var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

            var a = result.Properties.Items.Keys;

            // var googleTokenResponse = JsonConvert.DeserializeObject<GoogleTokenResponse>(result.Properties.Items["token_response"]);
            var googleAccessToken = result.Properties.Items[".Token.access_token"];

            // Use the Google access token to retrieve the user's information
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", googleAccessToken);
            var httpResponse = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v3/userinfo");
            if (!httpResponse.IsSuccessStatusCode)
            {
                // Handle failure
                return RedirectToAction(nameof(Login));
            }
            var googleUserInfoResponse = JsonConvert.DeserializeObject<GoogleUserInfoResponse>(await httpResponse.Content.ReadAsStringAsync());


            var userExists = db.Accounts.SingleOrDefault(x => x.Email == googleUserInfoResponse.Email);

            if (userExists != null)
            {
                // email này đã dki tài khoản rồi thì cho đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", userExists.AccountId);
                CurrentAccount.initSession(userExists.AccountId);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                const string defaultPassword = "default123";

                // tạo user mới và add vào db 
                var newUser = new Account
                {
                    // Avatar = GetAvatarLink(external),
                    Email = googleUserInfoResponse.Email,
                    DisplayName = googleUserInfoResponse.Email.Split("@")[0],
                    FullName = googleUserInfoResponse.Name,
                    Password = defaultPassword,
                    Avatar = googleUserInfoResponse.Picture
                };
                db.Accounts.Add(newUser);
                db.SaveChanges();

                // đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", newUser.AccountId);
                CurrentAccount.initSession(newUser.AccountId);
                return RedirectToAction("Index", "Home");

            }
        }

    }
    public class fbAccount
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }

    public class FacebookPicture
    {
        public FacebookPictureData Data { get; set; }
    }

    public class FacebookPictureData
    {
        public string Url { get; set; }
    }

    public class GoogleTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("id_token")]
        public string IdToken { get; set; }
    }

    public class GoogleUserInfoResponse
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("email")]
        public string Email { get; set; }

        [JsonPropertyName("verified_email")]
        public bool VerifiedEmail { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("given_name")]
        public string GivenName { get; set; }

        [JsonPropertyName("family_name")]
        public string FamilyName { get; set; }

        [JsonPropertyName("picture")]
        public string Picture { get; set; }

        [JsonPropertyName("locale")]
        public string Locale { get; set; }
    }
}
