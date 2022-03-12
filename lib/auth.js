"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; }; /* eslint no-underscore-dangle: 0 */


var _fs = require("fs");

var _fs2 = _interopRequireDefault(_fs);

var _path = require("path");

var _path2 = _interopRequireDefault(_path);

var _tapeRecorder = require("@minni-im/tape-recorder");

var _tapeRecorder2 = _interopRequireDefault(_tapeRecorder);

var _passport = require("passport");

var _passport2 = _interopRequireDefault(_passport);

var _passportGithub = require("passport-github");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const User = _tapeRecorder2.default.model("User");

const PROVIDER_NAME = "github";

class MinniAuthGithub {

  constructor(options) {
    this.options = Object.assign(MinniAuthGithub.defaults, options);
    if (!this.options.id || !this.options.secret || !this.options.callback) {
      throw new Error(`MinniAuthGithub setup error: Missing configuration
Pleasee check your id, secret and callback settings`);
    }
  }

  /**
   * Setup the passport authentication strategy
   * @api public
   */
  setup() {
    _passport2.default.use(new _passportGithub.Strategy({
      userAgent: this.options.userAgent,
      clientID: this.options.id,
      clientSecret: this.options.secret,
      callbackURL: this.options.callback,
      passReqToCallback: true
    }, (req, accessToken, refreshToken, profile, done) => {
      process.nextTick(() => {
        const { session } = req;
        if (session.authAction === "login") {
          delete session.authAction;
          return User.findByProviderId(PROVIDER_NAME, profile._json.id).then(user => {
            if (!user) {
              done(null, false, [`Sorry we don't know any « ${profile.displayName} » from Github.`, " You first need to signup before trying to login"].join(""));
            } else {
              done(null, user);
            }
          }, error => done(error));
        }

        // Connect account or Signup
        if (req.user) {
          // Connecting
          const localUser = req.user;
          localUser.providers = _extends({}, localUser.providers, {
            [PROVIDER_NAME]: profile._json.id
          });
          return localUser.save().then(user => {
            done(null, user, "Successfully registered Github as an authentication provider");
          }, error => done(error));
        }

        // Signup
        const user = new User({
          email: profile.emails[0].value,
          providers: {
            github: profile._json.id
          },
          avatar: profile._json.avatar_url
        });
        user.fullname = profile.displayName;
        return user.save().then(updatedUser => done(null, updatedUser), error => done(error));
      });
    }));
  }

  /**
   * Initialize an outgoing authentication request. Set a session flag to specify
   * that we are in a `login` action.
   *
   *     app.get("/login/github", this.initialize());
   *
   * @return {Array} middlewares to be executed.
   * @api public
   */
  initialize() {
    return [(req, res, next) => {
      const { session } = req;
      session.authAction = "login";
      next();
    }, _passport2.default.authenticate("github", {
      scope: this.options.scope
    })];
  }

  /**
   * Authenticate the request after coming back from provider.
   *
   *     app.get("/auth/github/callback", this.authenticate());
   *
   * @return {Array} middlewares to be executed.
   * @api public
   */
  authenticate() {
    return _passport2.default.authenticate("github", {
      successReturnToOrRedirect: this.options.successRedirect,
      failureRedirect: this.options.failureRedirect,
      successFlash: true,
      failureFlash: true
    });
  }

  /**
   * Authorize again the request. Usually used to associated new provider info
   * on an already logged in user.
   *
   *     app.get("/connect/github", this.connect());
   *
   * @return {Array} middlewares to be executed.
   * @api public
   */
  connect() {
    return _passport2.default.authorize("github", {
      successReturnToOrRedirect: this.options.successRedirect,
      failureRedirect: "/profile",
      successFlash: { type: "info" },
      failureFlash: true,
      scope: this.options.scope
    });
  }

  /**
   * Removes authorization associated with the current provider.
   *
   *     app.get("/connect/github/revoke", this.disconnect());
   *
   * @return {Array} middlewares to be executed.
   * @api public
   */
  disconnect() {
    return [(req, res, next) => {
      const { providers } = req.user;
      delete providers.github;
      req.user.save().then(() => {
        req.flash("info", "Github has been successfully unlinked from your account.");
        next();
      }, error => next(error));
    }, (req, res) => {
      let url = "/profile";
      const { session } = req;
      if (session && session.returnTo) {
        url = session.returnTo;
        delete session.returnTo;
      }
      res.redirect(url);
    }];
  }
}
exports.default = MinniAuthGithub;
MinniAuthGithub.defaults = {
  userAgent: "minni.im",
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  logo: new Buffer(_fs2.default.readFileSync(_path2.default.join(__dirname, "..", "public", "logo.png"))).toString("base64")
};