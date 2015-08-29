var GithubStrategy = require("passport-github").Strategy;

// Peer dependencies. So we rely on it but can't define it as direct dependencies
var passport = require("passport");
var recorder = require("recorder");

// Peer dependencies check
if (!recorder) {
  throw new Error("minni-im-github is a minni-app plugin, and can not be used outside of it");
}

var User = recorder.model("User");

function MinniAuthGithub(options) {
  this.options = options;
}

MinniAuthGithub.key = "github";

MinniAuthGithub.prototype.setup = function () {
  passport.use(new GithubStrategy({
    userAgent: this.options.userAgent || "minni.im",
    clientID: this.options.id,
    clientSecret: this.options.secret,
    callbackURL: this.options.callback
  }), callback(MinniAuthGithub.key));
};

MinniAuthGithub.prototype.signup = function () {
  // body...
};

MinniAuthGithub.prototype.authenticate = function (req, res, done) {
  passport.authenticate("github", { "failuer" }, done)(req, res);
};

module.exports = {
  auth: MinniAuthGithub
};
