require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const ejs = require("ejs");
const port = 3000;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "My little secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Database, Schemas, Encryption
mongoose.connect("mongodb://localhost:27017/userDB");

const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  name: String,
  secret: String,
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const User = new mongoose.model("User", UserSchema);
passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// Google Auth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { googleId: profile.id, name: profile.displayName },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

// Home Page
app.get("/", (req, res) => {
  res.render("home");
});

// Google OAuth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

// Login Page
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, (err) => {
    err
      ? console.log(err)
      : passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
  });
});

// Logout Page
app.get("/logout", (req, res) => {
  req.logout((err) => (err ? console.log(err) : res.redirect("/")));
});

// Register Page
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) =>
  User.find({ secret: { $ne: null } }, (err, foundUser) => {
    if (err) console.log(err);
    if (foundUser) {
      res.render("secrets", { usersWithSecrets: foundUser });
    }
  })
);

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      }

      if (!err) {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

// Submit secret
app.get("/submit", (req, res) => {
  return req.isAuthenticated() ? res.render("submit") : res.redirect("/login");
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, (err, foundUser) => {
    if (err) console.log(err);
    if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save(() => res.redirect("/secrets"));
    }
  });
});
app.listen(port, () => {
  console.log(`Listening on ${port}`);
});
