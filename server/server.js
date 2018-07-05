//ACCESS TOKEN EXISTS IN REQ.SIGNEDCOOKIES.ACCESSTOKEN
//INSTANCE OF ACCESSTOKEN MODEL IS NOT CREATED AFTER LOCAL LOGIN
//INSTANCE OF ACCESSTOKEN MODEL IS CREATED AFTER SOCIAL LOGIN
"use strict";

var loopback = require("loopback");
var boot = require("loopback-boot");
var app = (module.exports = loopback());
var cookieParser = require("cookie-parser");
var session = require("express-session");

// Passport configurators..
var loopbackPassport = require("loopback-component-passport");
var PassportConfigurator = loopbackPassport.PassportConfigurator;
var passportConfigurator = new PassportConfigurator(app);

/*
 * body-parser is a piece of express middleware that
 *   reads a form's input and stores it as a javascript
 *   object accessible through `req.body`
 *
 */
var bodyParser = require("body-parser");

/**
 * Flash messages for passport
 *
 * Setting the failureFlash option to true instructs Passport to flash an
 * error message using the message given by the strategy's verify callback,
 * if any. This is often the best approach, because the verify callback
 * can make the most accurate determination of why authentication failed.
 */
var flash = require("express-flash");

// attempt to build the providers/passport config
var config = {};
try {
  config = require("../providers.json");
} catch (err) {
  console.trace(err);
  process.exit(1); // fatal
}

// -- Add your pre-processing middleware here --

// Setup the view engine (jade)
var path = require("path");
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");

// boot scripts mount components like REST API
boot(app, __dirname);

// to support JSON-encoded bodies
app.middleware("parse", bodyParser.json());
// to support URL-encoded bodies
app.middleware(
  "parse",
  bodyParser.urlencoded({
    extended: true
  })
);

// The access token is only available after boot
app.middleware(
  "auth",
  loopback.token({
    model: app.models.accessToken
  })
);

app.middleware("session:before", cookieParser(app.get("cookieSecret")));
app.middleware(
  "session",
  session({
    secret: "kitty",
    saveUninitialized: true,
    resave: true
  })
);
passportConfigurator.init();

// We need flash messages to see passport errors
app.use(flash());

passportConfigurator.setupModels({
  userModel: app.models.user,
  userIdentityModel: app.models.userIdentity,
  userCredentialModel: app.models.userCredential
});
for (var s in config) {
  var c = config[s];
  c.session = c.session !== false;
  passportConfigurator.configureProvider(s, c);
}
var ensureLoggedIn = require("connect-ensure-login").ensureLoggedIn;

//Overrides factory ACL's
app.models.user.settings.acls = require("./user-acls.json");

app.get("/", function(req, res, next) {
  res.render("pages/index", {
    user: req.user,
    url: req.url
  });
});

app.get("/auth/account", ensureLoggedIn("/login"), function(req, res, next) {
  console.log("/auth/account HIT");

  if (!req.accessToken) {
    console.log("in IF");
    app.models.accessToken
      .findOne({ userId: req.user.id })
      .then(token => {
        req.accessToken = token;
        console.log("TOKEN: ", token);
        res.cookie("access_token", token.id, {
          signed: true,
          maxAge: 1000 * token.ttl
        });
        res.cookie("userId", token.userId, {
          signed: true,
          maxAge: 1000 * token.ttl
        });
      })
      .then(() => res.redirect("/auth/account"));
  } else {
    console.log("in ELSE");
    res.render("pages/loginProfiles", {
      user: req.user,
      url: req.url
    });
  }
});

app.get("/local", function(req, res, next) {
  res.render("pages/local", {
    user: req.user,
    url: req.url
  });
});

app.get("/ldap", function(req, res, next) {
  res.render("pages/ldap", {
    user: req.user,
    url: req.url
  });
});

app.get("/signup", function(req, res, next) {
  res.render("pages/signup", {
    user: req.user,
    url: req.url
  });
});

app.post("/signup", function(req, res, next) {
  var User = app.models.user;

  var newUser = {};
  newUser.email = req.body.email.toLowerCase();
  newUser.username = req.body.username.trim();
  newUser.password = req.body.password;

  User.create(newUser, function(err, user) {
    if (err) {
      req.flash("error", err.message);
      return res.redirect("back");
    } else {
      // Passport exposes a login() function on req (also aliased as logIn())
      // that can be used to establish a login session. This function is
      // primarily used when users sign up, during which req.login() can
      // be invoked to log in the newly registered user.
      req.login(user, function(err) {
        console.log("User: ", user);
        if (err) {
          req.flash("error", err.message);
          return res.redirect("back");
        }
        return User.login(
          { username: newUser.username, password: newUser.password },
          (err, token) => {
            if (err) {
              console.log(`ERROR LOGIN IN::: ${err}`);
              req.flash("error", err.message);
              return res.redirect("back");
            }
            //Manually set cookies here
            res.cookie("access_token", token.id, {
              signed: true,
              maxAge: 1000 * token.ttl
            });
            res.cookie("userId", token.userId, {
              signed: true,
              maxAge: 1000 * token.ttl
            });

            return res.redirect("/auth/account");
          }
        );
      });
    }
  });
});

app.get("/login", function(req, res, next) {
  res.render("pages/login", {
    user: req.user,
    url: req.url
  });
});

app.get("/auth/logout", function(req, res, next) {
  app.models.accessToken
    .remove({ userId: req.user.id })
    .then(token => console.log("DELETED: ", token)); //Remove token from database
  res.clearCookie("access_token"); //clear cookie
  res.clearCookie("userId"); //clear cookie
  req.logout(); //Log out
  res.redirect("/"); //Redirect to landing page
});

app.start = function() {
  // start the web server
  return app.listen(function() {
    app.emit("started");
    var baseUrl = app.get("url").replace(/\/$/, "");
    console.log("Web server listening at: %s", baseUrl);
    if (app.get("loopback-component-explorer")) {
      var explorerPath = app.get("loopback-component-explorer").mountPath;
      console.log("Browse your REST API at %s%s", baseUrl, explorerPath);
    }
  });
};

// start the server if `$ node server.js`
if (require.main === module) {
  app.start();
}
