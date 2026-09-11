require("dotenv").config({ quiet: true });

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.ADMIN_PASSWORD || !process.env.SESSION_SECRET) {
  console.error("Missing ADMIN_PASSWORD or SESSION_SECRET in .env");
  process.exit(1);
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.set("trust proxy", 1);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    name: "bm.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

function passwordMatches(input) {
  const a = crypto.createHash("sha256").update(String(input)).digest();
  const b = crypto.createHash("sha256").update(process.env.ADMIN_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

function requireAuth(req, res, next) {
  if (req.session.isAdmin) return next();
  res.redirect("/login");
}

// Public routes
app.get("/login", (req, res) => {
  if (req.session.isAdmin) return res.redirect("/");
  res.render("login", { title: "Sign in", error: null });
});

app.post("/login", (req, res, next) => {
  if (!passwordMatches(req.body.password || "")) {
    return res.status(401).render("login", {
      title: "Sign in",
      error: "Incorrect password. Try again.",
    });
  }
  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.isAdmin = true;
    req.session.save((err) => {
      if (err) return next(err);
      res.redirect("/");
    });
  });
});

app.post("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("bm.sid");
    res.redirect("/login");
  });
});

// Everything below requires login
app.use(requireAuth);

app.get("/", (req, res) => {
  res.render("index", { title: "Bright Moon" });
});

if (!isProduction) {
  app.get("/test-500", () => {
    throw new Error("Test error");
  });
}

// 404
app.use((req, res) => {
  res.status(404).render("404", { title: "Page not found" });
});

// 500
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).render("500", { title: "Something went wrong" });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});