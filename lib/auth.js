var fs = require("fs");
var path = require("path");
var passport = require("passport");
var recorder = require("tape-recorder");
var GithubStrategy = require("passport-github").Strategy;

var User = recorder.model("User");

function MinniAuthGithub(options) {
  this.options = Object.assign(MinniAuthGithub.defaults, options);
  if (!this.options.id ||
      !this.options.secret ||
      !this.options.callback) {
    throw new Error("MinniAuthGithub setup error: missing configuration. Pleasee check your id, secret and callback settings");
  }
}

MinniAuthGithub.defaults = {
  userAgent: "minni.im",
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  logo: new Buffer(fs.readFileSync(path.join(__dirname, "..", "public", "logo.png"))).toString("base64")
};

/**
 * Setup the passport authentication strategy
 * @api public
 */
MinniAuthGithub.prototype.setup = function () {
  passport.use(new GithubStrategy({
    userAgent: this.options.userAgent,
    clientID: this.options.id,
    clientSecret: this.options.secret,
    callbackURL: this.options.callback,
    passReqToCallback: true,
  }, function (req, accessToken, refreshToken, profile, done) {
    process.nextTick(function() {
      if (req.session.authAction === "login") {
        delete req.session.authAction;
        return User.findByProviderId("github", profile._json.id)
          .then(function(user) {
            if (!user) {
              done(null, false, "Sorry we don't know any « " + profile.displayName + " » from Github. You first need to signup before trying to login");
            } else {
              done(null, user);
            }
          }, function(error) {
            console.error(error);
            done(error);
          });
      } else {
        // Connect account or Signup
        if (req.user) {
          // Connecting
          var localUser = req.user;
          localUser.providers["github"] = profile._json.id;
          return localUser.save()
            .then(function(user) {
              done(null, user, "Successfully registered Github as an authentication provider");
            }, function(error) {
              done(error);
            });
        } else {
          // Signup
          var user = new User({
            email: profile.emails[0].value,
            providers: {
              github: profile._json.id
            },
            avatar: profile._json.avatar_url
          });
          user.fullname = profile.displayName;
          return user.save()
            .then(function(user) {
              done(null, user);
            }, function(error) {
              done(error);
            });
        }
      }
    });
  }));
};

/**
 * Initialize an outgoing authentication request. Set a session flag to specify
 * that we are in a `login` action.
 *
 *     app.get("/login/github", this.initialize());
 *
 * @return {Array} middlewares to be executed.
 * @api public
 */
MinniAuthGithub.prototype.initialize = function () {
  return [
    function (req, res, next) {
      req.session.authAction = "login";
      next();
    },
    passport.authenticate("github", {
      scope: this.options.scope
    })
  ];
};

/**
 * Authenticate the request after coming back from provider.
 *
 *     app.get("/auth/github/callback", this.authenticate());
 *
 * @return {Array} middlewares to be executed.
 * @api public
 */
MinniAuthGithub.prototype.authenticate = function () {
  return passport.authenticate("github", {
    successReturnToOrRedirect: this.options.successRedirect,
    failureRedirect: this.options.failureRedirect,
    successFlash: true,
    failureFlash: true
  });
};

/**
 * Authorize again the request. Usually used to associated new provider info
 * on an already logged in user.
 *
 *     app.get("/connect/github", this.connect());
 *
 * @return {Array} middlewares to be executed.
 * @api public
 */
MinniAuthGithub.prototype.connect = function () {
  return passport.authorize("github", {
    successReturnToOrRedirect: this.options.successRedirect,
    failureRedirect: "/profile",
    successFlash: { type: "info" },
    failureFlash: true,
    scope: this.options.scope
  });
};

/**
 * Removes authorization associated with the current provider.
 *
 *     app.get("/connect/github/revoke", this.disconnect());
 *
 * @return {Array} middlewares to be executed.
 * @api public
 */
MinniAuthGithub.prototype.disconnect = function () {
  return [ function (req, res, next) {
    delete req.user.providers.github;
    req.user.save().then(function() {
      req.flash("info", "Github has been successfully unlinked from your account.");
      next();
    }, function(error) {
      next(error);
    });
  }, function (req, res) {
    var url = "/profile";
    if (req.session && req.session.returnTo) {
      url = req.session.returnTo;
      delete req.session.returnTo;
    }
    res.redirect(url);
  }];
}

module.exports = MinniAuthGithub;
