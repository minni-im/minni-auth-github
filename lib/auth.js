var passport = require("passport");
var recorder = require("tape-recorder");
var GithubStrategy = require("passport-github").Strategy;

var User = recorder.model("User");

function MinniAuthGithub(options) {
  this.options = Object.assign(MinniAuthGithub.defaults, options);
  if (!this.options.id || !this.options.secret || !this.options.callback) {
    throw new Error("MinniAuthGithub setup error: missing configuration. Pleasee check your id, secret and callback settings");
  }
}

MinniAuthGithub.defaults = {
  userAgent: "minni.im",
  initialize: {},
  authenticate: {
    successRedirect: "/",
    failureRedirect: "/login",
    flashMessage: true
  }
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
    callbackURL: this.options.callback
  }, function (accessToken, refreshToken, user, done) {
    return MinniAuthGithub.findOrCreate(user, done);
  }));
};

/**
 * Initialize the first auth redirection. Usually used on the first request to authenticate
 *
 *     app.get("/login/github", ... );
 *
 * @return {Middleware} middleware authentication function.
 * @api public
 */
MinniAuthGithub.prototype.initialize = function() {
  return passport.authenticate("github", this.options.initialize);
}

/**
 * Authenticate the request. Usually done when the auth provider calls us back
 *
 *     app.get("/auth/github/callback", ... );
 *
 * @return {Middleware} middleware authentication function.
 * @api public
 */
MinniAuthGithub.prototype.authenticate = function (req, res, done) {
  passport.authenticate("github", done)(req, res);
};

/**
 * Authenticate again the request. Usually used to associated new provider info
 * on an already logged in user.
 *
 * @return {Middleware} middleware authentication function.
 * @api public
 */
MinniAuthGithub.prototype.connect = function () {
  return passport.authorize("github", this.options.initialize);
};


MinniAuthGithub.findOrCreate = function(user, done) {
  User.findByProviderId("github", user._json.id)
    .then(function(user) {
      return done(null, user || false);
    }, function(error) {
      return done(error);
    });
};

module.exports = MinniAuthGithub;
