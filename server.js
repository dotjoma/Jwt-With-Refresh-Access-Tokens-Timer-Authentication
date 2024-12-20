const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const path = require("path");
const csrf = require("csurf");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());
app.use(express.json());
app.use(cookieParser());
app.use(cookieParser());

const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY;

// Setup CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

// Apply CSRF protection to all POST routes
app.use(csrfProtection);

// Route to get CSRF token
app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// MySQL connection
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("[SUCCESS] Connected to MySQL!");
});

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Serve index.html for the root URL
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/register", csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  // Check if user already exists
  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ error: "Error checking user existence" });
      }
      if (results.length > 0) {
        return res.status(400).json({ error: "User already exists" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Store user
      connection.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        (err, results) => {
          if (err) {
            return res.status(500).json({ error: "Error registering user" });
          }
          console.log(`[INFO] User registered: ${username}`);
          res
            .status(201)
            .json({ message: "Registration successful. Please log in." });
        }
      );
    }
  );
});

// Login endpoint
app.post("/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  // Check if user exists
  connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ error: "Error checking user existence" });
      }
      if (results.length === 0) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      const user = results[0];
      // Compare password
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      // Generate Access Token
      const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, {
        expiresIn: "24h", // Access token expires in 15 minutes
      });

      // Generate Refresh Token
      const refreshToken = jwt.sign(
        { username: user.username },
        REFRESH_SECRET_KEY,
        {
          expiresIn: "7d", // Refresh token expires in 7 days
        }
      );

      console.log(`[INFO] Tokens generated for user: ${username}`);
      console.log(`[INFO] Access Token: ${accessToken}`);
      console.log(`[INFO] Refresh Token: ${refreshToken}`);

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
      });
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
      });
      res.json({ message: "Login successful", accessToken });
    }
  );
});

// Refresh token endpoint
app.post("/refresh-token", csrfProtection, (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token not provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET_KEY);
    const accessToken = jwt.sign({ username: decoded.username }, SECRET_KEY, {
      expiresIn: "24h",
    });
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    });
    res.json({ message: "Access token refreshed", accessToken });
    console.log(`Access token refreshed for: ${decoded.username}`);
  } catch (err) {
    res.status(401).json({ error: "Invalid refresh token" });
  }
});

// Logout endpoint
app.post("/logout", csrfProtection, (req, res) => {
  // Clear the access token and refresh token cookies
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

  // Optionally clear any other cookies related to authentication
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

  res.json({ message: "Logout successful" });
});

// Protected endpoint example
app.get("/protected", csrfProtection, (req, res) => {
  const { accessToken } = req.cookies;

  if (!accessToken) {
    return res.status(401).json({ error: "Access token not provided" });
  }

  try {
    const decoded = jwt.verify(accessToken, SECRET_KEY);
    res.json({ message: "Protected content", user: decoded });
  } catch (err) {
    console.error("Error verifying access token:", err);
    res.status(401).json({ error: "Invalid access token" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
