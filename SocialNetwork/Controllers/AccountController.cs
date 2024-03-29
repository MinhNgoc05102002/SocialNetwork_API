﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
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
                    if (account.IsBanned == true)
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
            account.Gender = model.Gender;
            account.DayOfBirth = model.DayOfBirth;
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
            return Json(new { success = true });
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

            return Json(new { success = true, message = "Image uploaded successfully" });
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
            //var fbUserAvatar = result.Principal.FindFirstValue("Picture");

            var client = new HttpClient();

            var responseImg = await client.GetAsync($"https://graph.facebook.com/v11.0/{fbUserId}/picture?type=large&redirect=false&access_token={accessToken}");
            var img = await responseImg.Content.ReadAsStringAsync();
            var pictureData = JsonConvert.DeserializeObject<FacebookPicture>(img);

            var userExists = db.Accounts.SingleOrDefault(x => x.Email == fbUserEmail);

            if (userExists != null)
            {
                // email này đã dki tài khoản rồi thì cho đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", userExists.AccountId);
                CurrentAccount.initSession(userExists.AccountId);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                // tạo user mới và add vào db 
                const string defaultPassword = "default123";
                var newUser = new Account
                {
                    Email = fbUserEmail,
                    DisplayName = fbUserEmail.Split("@")[0],
                    FullName = fbUserName,
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

        
        [HttpGet]
        public async Task<IActionResult> CallbackLoginGoogle()
        {
            var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            // chưa có check đăng nhập lỗi 
            var accessToken = result.Properties.GetTokenValue("access_token");
            var UserId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var UserName = result.Principal.FindFirstValue(ClaimTypes.Name);
            var UserEmail = result.Principal.FindFirstValue(ClaimTypes.Email);

            // mặc định ko có cái picture nhưng mình đã config thêm nó vào trong program.cs
            var Picture = result.Principal.FindFirstValue("Picture");

            var userExists = db.Accounts.SingleOrDefault(x => x.Email == UserEmail);

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
                    Email = UserEmail,
                    DisplayName = UserEmail.Split("@")[0],
                    FullName = UserName,
                    Password = defaultPassword,
                    Avatar = Picture,
                    DayOfBirth = DateTime.Now
                };
                db.Accounts.Add(newUser);
                db.SaveChanges();

                // đăng nhập luôn 
                HttpContext.Session.SetInt32("accountId", newUser.AccountId);
                CurrentAccount.initSession(newUser.AccountId);
                return RedirectToAction("Index", "Home");

            }
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }
    }

    public class FacebookPicture
    {
        public FacebookPictureData Data { get; set; }
    }

    public class FacebookPictureData
    {
        public string Url { get; set; }
    }

}
