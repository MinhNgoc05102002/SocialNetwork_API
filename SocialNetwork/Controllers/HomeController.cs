using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using SocialNetwork.Models;
using SocialNetwork.Models.Authentication;
using SocialNetwork.ViewModels;
using System.Diagnostics;
using IHostingEnvironment = Microsoft.AspNetCore.Hosting.IHostingEnvironment;

namespace SocialNetwork.Controllers
{
    public class HomeController : Controller
    {
        private IHostingEnvironment _env;
        private readonly ILogger<HomeController> _logger;
        private SocialNetworkDbContext context = new SocialNetworkDbContext();

        public HomeController(ILogger<HomeController> logger, IHostingEnvironment _enviroment)
        {
            _logger = logger;
            _env = _enviroment;
        }

        [Authentication]
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        //POST OPTION
        [HttpPost]
        public IActionResult CreatePost(string Content, List<IFormFile> images,string lng,string lat)
        {
            Post post = new Post();
            post.AccountId = CurrentAccount.account.AccountId;
            post.Content = Content;
            post.CreateAt = DateTime.Now;
            post.LikeCount = 0;
            post.Lat = lat;
            post.Long = lng;
            post.CommentCount = 0;
            post.IsDeleted = false;
            context.Posts.Add(post);
            context.SaveChanges();
            foreach (var image in images)
            {
                if (image != null)
                {
                    string serverMapPath = Path.Combine(_env.WebRootPath, $"images/post/{CurrentAccount.account.AccountId}/{post.PostId}");
                    string serverMapPathFile = Path.Combine(serverMapPath, image.FileName);
                    Directory.CreateDirectory(serverMapPath);
                    using (var stream = new FileStream(serverMapPathFile, FileMode.Create))
                    {
                        image.CopyTo(stream);
                    }
                    string filepath = $"/images/post/{CurrentAccount.account.AccountId}/{post.PostId}/{image.FileName}";
                    Medium medium = new Medium();
                    medium.PostId = post.PostId;
                    medium.MediaLink = filepath.ToString();
                    if (image.ContentType.Contains("image"))
                    {
                        medium.MediaType = "image";
                    }
					else if (image.ContentType.Contains("video"))
					{
						medium.MediaType = "video";
					}
					context.Media.Add(medium);
				}
			}
			context.SaveChanges();
			PostDetailViewModel postDetail = new PostDetailViewModel(post);
			// thôi chịu khó lấy ra từng cái 1 :,)
			return new ObjectResult(new { 
				id = post.PostId,
				idUser = postDetail.GetPostOwnerAccount().AccountId,
				nameAuthor = postDetail.GetPostOwnerAccount().FullName,
				avatarAuthor = postDetail.GetPostOwnerAccount().Avatar,
                createAt = post.CreateAt,
				content = post.Content,
				listLike = postDetail.GetListAccountLiked().Count(),
				imagesPost = postDetail.GetListMedia(),
                lat = post.Lat,
                lng = post.Long
			});
		}

		[HttpDelete]
        public IActionResult DeletePost(string postId)
        {
            Post post = context.Posts.SingleOrDefault(x => x.PostId.ToString() == postId);
			if (post != null && CurrentAccount.account.AccountId == post.AccountId)
			{
				post.IsDeleted = true;
				context.Entry(post).State = EntityState.Modified;
				context.SaveChanges();
				return Json(true);
			}
			
            return Json(false);
        }

        [Route("~/p/{postId}")]
        public IActionResult SinglePostDetail(int postId)
        {
            var singlePost = context.Posts.SingleOrDefault(x => x.PostId == postId && x.IsDeleted == false);
            if (singlePost == null)
            {
                return RedirectToAction("Index");
            }
            var singlePostDetail = new ViewModels.PostDetailViewModel(singlePost);
            return View(singlePostDetail);
        }

        [HttpGet]
        public IActionResult GetPostById(int postId)
        {
            var singlePost = context.Posts.SingleOrDefault(x => x.PostId == postId && x.IsDeleted == false);
            if (singlePost == null)
            {
                string message = "Error";
                return Json(new { message });
            }
            var singlePostDetail = new ViewModels.PostDetailViewModel(singlePost);
            var lstMedial = singlePostDetail.GetListMedia();
            return Json(new { singlePostDetail, lstMedial });
        }

        [HttpPut]
        public IActionResult UpdatePostById(int postId, string newcontent)
        {
            var singlePost = context.Posts.SingleOrDefault(x => x.PostId == postId && x.IsDeleted == false);
            if (singlePost == null || CurrentAccount.account.AccountId != singlePost.AccountId)
            {
                string message = "Post isn't exist or you dont have role";
                return Json(new { message });
            }
            singlePost.Content = newcontent;
            context.SaveChanges();
            return Json(new { singlePost });
        }

        public IActionResult Weather()
        {
            return View();
        }
    }
}