using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace SimpleLogIn.Controllers
{
    public class UserController : Controller
    {
        //
        // GET: /User/

        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult LogIn()
        {
            return View();
        }
        [HttpPost]
        public ActionResult LogIn(SimpleLogIn.Models.UserModel user)
        {
            if (ModelState.IsValid)
            {
                if (IsValid(user.Email, user.Password))
                {
                    FormsAuthentication.SetAuthCookie(user.Email, false);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Incorrect Email or Password");
                }
            }
            return View(user);
        }
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Registration(SimpleLogIn.Models.UserModel user)
        {
            if(ModelState.IsValid)
            {
            using (var db = new MainDBEntities())
            {
                var crypto = new SimpleCrypto.PBKDF2();
                var encrypPass = crypto.Compute(user.Password);
                var sysUser = db.SystemUsers.Create();
                sysUser.Email = user.Email;
                sysUser.Password = encrypPass;
                sysUser.PasswordSalt = crypto.Salt;
                sysUser.UserID = Guid.NewGuid();

                db.SystemUsers.Add(sysUser);
                db.SaveChanges();
                return RedirectToAction("Index","Home");
            }
            }
                else 
                {
                    ModelState.AddModelError("","Incorrect Email or Password Entry");
                }
            
            return View();
        }

        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }
        private bool IsValid(string email, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool isValid = false;
            using (var db = new MainDBEntities())
            {
                var user = db.SystemUsers.FirstOrDefault(u => u.Email == email);
                if (user != null)
                {
                    if (user.Password == crypto.Compute(password, user.PasswordSalt))
                    {
                        isValid = true;
                    }
                }
            }
            return isValid;

        }
    }
}
