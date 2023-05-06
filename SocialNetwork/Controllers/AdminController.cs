using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SocialNetwork.Models;
using SocialNetwork.Models.Authentication;
using X.PagedList;

namespace SocialNetwork.Controllers
{
    public class AdminController : Controller
    {

        SocialNetworkDbContext context = new SocialNetworkDbContext();
        [Authentication]
        public IActionResult Index(int? page)
        {
            // CurrentAccount.initSession(1);
            int currentAccountID = (int)HttpContext.Session.GetInt32("accountId");

            Account currentAccount = context.Accounts.Find(currentAccountID);

            if (currentAccount.IsAdmin == true)
            {
                int pageNumber = page == null || page < 1 ? 1 : page.Value;
                int pageSise = 5;
                var listAccount = context.Accounts.AsNoTracking().OrderBy(x => x.AccountId).ToList();
                PagedList<Account> list = new PagedList<Account>(listAccount, pageNumber, pageSise);
                return View(list);
            }
            return RedirectToAction("Index", "Home");
        }

        [Authentication]
        [HttpPut]
        public IActionResult BanAccount(int? accountId)
        {

            //if (CurrentAccount.account.IsAdmin == true)
            // int? currentAccountID = HttpContext.Session.GetInt32("accountId");
            // Account currentAccount = context.Accounts.Find(currentAccountID);
            string message = "";
            bool? isBan = false, status;
            if (CurrentAccount.account.IsAdmin == true)
            {
                Account accountBan = context.Accounts.SingleOrDefault(x => x.AccountId == accountId);
                if (accountBan != null && accountBan.IsAdmin == false)
                {
                    accountBan.IsBanned = !accountBan.IsBanned;
                    context.Entry(accountBan).State = EntityState.Modified;
                    context.SaveChanges();
                    message = "Changes has been saved ";
                    status = true;
                    isBan = accountBan.IsBanned;
                    return Json(new { status, message, isBan });
                }
                message = "Changes hasn't been saved ";
                status = false;
                return Json(new { status, message, isBan });
            }

            return RedirectToAction("Index", "Home");
        }
    }
}
