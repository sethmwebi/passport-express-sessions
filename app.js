const express = require("express");
const { v4: uuidv4 } = require("uuid");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const path = require("path");
const bodyParser = require("body-parser");
const localStrategy = require("passport-local").Strategy;
const passport = require("passport");
const bcrypt = require("bcryptjs");
const fs = require("fs").promises;
const users = require("./users.json");

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));

app.use(
  session({
    genid: (req) => {
      console.log("1. in genid req.sessionID: ", req.sessionID);
      return uuidv4();
    },
    store: new FileStore(),
    secret: "prudence",
    resave: false,
    saveUninitialized: false,
  }),
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  console.log("in serialize user: ", user);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log("in deserialize user: ", user);
  done(null, user);
});

passport.use(
  "signup",
  new localStrategy(async (username, password, done) => {
    try {
      if (password.length <= 4 || !username) {
        done(null, false, {
          message: "Your credentials do not match our criteria...",
        });
      } else {
        const hashedPass = await bcrypt.hash(password, 10);
        let newUser = { username, password: hashedPass, id: uuidv4() };
        users.push(newUser);
        await fs.writeFile("users.json", JSON.stringify(users), (err) => {
          if (err) return done(err);
          console.log("updated the fake database");
        });
        done(null, newUser, { message: "Signed up message!" });
      }
    } catch (error) {
      return done(error);
    }
  }),
);

passport.use(
  "login",
  new localStrategy(async (username, password, done) => {
    // done(null, userObject, { message: "Optional success/fail message"})
    // done(err) // application error
    // done(null, false, { message: "unauthorized login credentials!"}) // user input error when 2nd param is false
    try {
      const user = users.find((user) => user.username === username);

      if (!user) {
        return done(null, false, { message: "User not found!" });
      }

      const passwordMatches = await bcrypt.compare(password, user.password);

      if (!passwordMatches) {
        return done(null, false, { message: "Invalid credentials!" });
      }

      return done(null, user, { message: "Hey congrats, you are logged in!" });
    } catch (error) {
      return done(error);
    }
  }),
);

app.get("/", (req, res) => {
  console.log("get / req.sessionID: ", req.sessionID);
  console.log("req.session.user: ", req.session.user);
  console.log("req.session: ", req.session);
  res.send("get index route. /");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/success", (req, res) => {
  console.log("req.query: ", req.query);
  console.log("req.isAuthenticated: ", req.isAuthenticated());
  res.send("success");
});

app.get("/failed", (req, res) => {
  console.log("req.session: ", req.session);
  res.send("failed");
});

app.get("/logout", (req, res) => {
  req.logout(function(err) {
    if (err) next(err);
    res.redirect("/");
  });
});

app.get("/secureroute", (req, res) => {
  if (req.isAuthenticated()) {
    res.send("Welcome to the top secret place " + req.user.username);
  } else {
    res.send("Must log in first. visit /login");
  }
});

app.post("/login", function(req, res, next) {
  console.log("useless function");
  passport.authenticate("login", async (err, user, info) => {
    console.log("err: ", err);
    console.log("user: ", user);
    console.log("info: ", info);

    req.login(user, async (error) => {
      return res.redirect(`success?message=${info.message}`);
    });
  })(req, res, next);
});

app.post("/signup", (req, res, next) => {
  passport.authenticate("signup", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.redirect(`/failed?message=${info.message}`);
    }

    req.login(user, async (error) => {
      if (error) {
        return next(error);
      }

      return res.redirect(`/success?message=${info.message}`);
    });
  })(req, res, next);
});

app.listen(3000, () => {
  console.log("listening on port 3000");
});
