using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SocialNetwork.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

var connectionString = builder.Configuration.GetConnectionString("SocialNetworkDbContext");
builder.Services.AddDbContext<SocialNetworkDbContext>(x => x.UseSqlServer(connectionString));


builder.Services.AddSession();

builder.Services.AddAuthentication(options =>
{
    options.DefaultChallengeScheme = "Google"; // scheme sẽ được sử dụng khi gọi Challenge() cho Google authentication
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme; // scheme sẽ được sử dụng khi đăng nhập thành công
    //options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    //options.DefaultChallengeScheme = FacebookDefaults.AuthenticationScheme;
})
.AddCookie()
.AddFacebook("Facebook", options =>
{
    options.AppId = builder.Configuration["Facebook:AppId"];
    options.AppSecret = builder.Configuration["Facebook:AppSecret"];
    options.CallbackPath = builder.Configuration["Facebook:CallbackPath"];
    options.SaveTokens = true;
    options.ClaimActions.MapJsonKey("Picture", "picture.data.url");
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Google:AppId"];
    options.ClientSecret = builder.Configuration["Google:AppSecret"];
    options.CallbackPath = builder.Configuration["Google:CallbackPath"];
    options.SaveTokens = true;
    options.ClaimActions.MapJsonKey("Picture", "picture", "url"); // để có thể gọi Claim.Picture
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
