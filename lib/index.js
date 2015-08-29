var GithubStrategy = require("passport-github").Strategy;

// Peer dependencies. So we rely on it but can't define it as direct dependencies
var passport = require("passport");
var recorder = require("tape-recorder");

// Peer dependencies check
if (!recorder) {
  throw new Error("minni-im-github is a minni-app plugin, and can not be used outside of it");
}

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

MinniAuthGithub.key = "github";
MinniAuthGithub.findOrCreate = function(user, done) {
  done();
};

module.exports = {
  auth: MinniAuthGithub
};
