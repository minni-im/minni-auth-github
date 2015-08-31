var passport = require("passport");
var recorder = require("tape-recorder");
var GithubStrategy = require("passport-github").Strategy;

var User = recorder.model("User");

function MinniAuthGithub(options) {
  this.options = options;
}

MinniAuthGithub.prototype.setup = function () {
  passport.use(new GithubStrategy({
    userAgent: this.options.userAgent || "minni.im",
    clientID: this.options.id,
    clientSecret: this.options.secret,
    callbackURL: this.options.callback
  }, function (accessToken, refreshToken, user, done) {
    return MinniAuthGithub.findOrCreate(user, done);
  }));
};

MinniAuthGithub.prototype.authenticate = function (req, res, done) {
  passport.authenticate("github", {}, done)(req, res);
};

MinniAuthGithub.prototype.signup = function (req, res, done) {
  passport.authenticate("github", {}, done)(req, res);
};


MinniAuthGithub.key = "github";
MinniAuthGithub.findOrCreate = function(user, done) {
  done();
};

module.exports = MinniAuthGithub;
