require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");


// Models & routes
const authModel = require("./Models/Model");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");

const PORT = process.env.PORT || 8080;

/* =======================
   MongoDB (SINGLE connection)
======================= */
mongoose
  .connect(process.env.MONGO_URI, {
    family: 4,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

const app = express();

/* =======================
   Middleware
======================= */
app.use(
  cors({
    origin: process.env.FRONTEND_DOMAIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =======================
   Session store (reuse mongoose connection)
======================= */
const sessionStore = MongoStore.create({
  client: mongoose.connection.getClient(),
  collectionName: "session",
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,              // ✅ important
    saveUninitialized: false,   // ✅ important
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

/* =======================
   Passport (AFTER session)
======================= */
require("./passport");

app.use(passport.initialize());
app.use(passport.session());

/* =======================
   Routes
======================= */
app.get("/", (req, res) => {
  res.json("hello");
});

app.post("/register", async (req, res) => {
  try {
    const { userName, email, password } = req.body;

    const existingUser = await authModel.findOne({ email });
    if (existingUser) return res.json("Already Registered");

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new authModel({
      userName,
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (err) {
    res.status(400).json(err.message);
  }
});

// Local login
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: process.env.FRONTEND_DOMAIN,
  }),
  (req, res) => {
    res.json({ success: "successfully logged in" });
  }
);

// Logout
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json(err);
    res.json({ success: "logged out" });
  });
});

app.get("/getUser", (req, res) => {
  if (req.user) return res.json(req.user);
  res.status(401).json({ error: "Login Required" });
});

/* =======================
   Forgot / Reset Password
======================= */
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;

  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err) => {
    if (err) return res.send({ Status: "Try again later" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await authModel.findByIdAndUpdate(id, { password: hashedPassword });
    res.send({ Status: "success" });
  });
});

app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  const user = await authModel.findOne({ email });
  if (!user) return res.send({ Status: "Enter a valid email" });

  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "1d" }
  );

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER, // ❗ move to .env
      pass: process.env.EMAIL_PASS, // ❗ move to .env
    },
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Forgot password for task manager",
    text: `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`,
  });

  res.send({ Status: "success" });
});

/* =======================
   Protected routes
======================= */
const authenticator = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Login Required" });
  }
  next();
};

app.use("/todo", authenticator, TodoRoutes);
app.use("/note", authenticator, NoteRoutes);
app.use("/task", authenticator, TaskRoutes);

/* =======================
   Server
======================= */
app.listen(PORT, () => {
  console.log(`Server Running On Port : ${PORT}`);
});

module.exports = app;
