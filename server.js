const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const axios = require("axios");
const bcrypt = require("bcrypt");
const https = require("https");
const flash = require("connect-flash");

dotenv.config();
const app = express();
const PORT = 3000;

// Create a custom HTTPS agent to ignore SSL certificate errors
const httpsAgent = new https.Agent({
  rejectUnauthorized: false,
});
axios.defaults.httpsAgent = httpsAgent;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(flash());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session setup
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use((req, res, next) => {
  res.locals.user = req.session.user || null; // Pass user to all views
  res.locals.successMessage = req.flash("success");
  res.locals.errorMessage = req.flash("error");
  next();
});

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((error) => console.error("MongoDB connection error:", error));

// Schemas and Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
  deletedAt: Date,
});

const api1Schema = new mongoose.Schema({
  title: String,
  description: String,
  url: String,
  publishedAt: Date,
  source: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const api2Schema = new mongoose.Schema({
  text: String,
  author: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});

const historySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  action: { type: String, required: true },
  input: { type: String },
  date: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const API1 = mongoose.model("API1", api1Schema);
const API2 = mongoose.model("API2", api2Schema);
const History = mongoose.model("History", historySchema);

// Middleware to check session
function isAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/"); // Redirect to login if not authenticated
  }
  next();
}

// Routes
app.get("/", (req, res) => res.render("login"));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for username: ${username}`);
  const user = await User.findOne({ username });
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.user = user;
    return res.redirect("/main");
  }
  req.flash("error", "Wrong username or password, please try again.");
  res.redirect("/");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash("error", "Username already exists. Please choose another.");
      return res.redirect("/signup");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // Save the user to MongoDB
    await newUser.save();

    // Add success message and redirect to login
    req.flash("success", "Account created successfully. Please log in.");
    res.redirect("/");
  } catch (error) {
    console.error("Error during sign-up:", error);
    req.flash("error", "An error occurred. Please try again.");
    res.redirect("/signup");
  }
});

app.get("/main", isAuthenticated, (req, res) => {
  res.render("main", { username: req.session.user.username });
});

app.get("/history", isAuthenticated, async (req, res) => {
  try {
    const history = await History.find({ userId: req.session.user._id }).sort({
      date: -1,
    });
    res.render("history", { username: req.session.user.username, history });
  } catch (error) {
    console.error("Error fetching history:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/admin", isAuthenticated, async (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.status(403).send("Access denied");
  }
  try {
    const users = await User.find();
    res.render("admin", { users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/admin/add", isAuthenticated, async (req, res) => {
  console.log(req.body); // Log the request body to debug issues

  const { username, password, isAdmin } = req.body;

  if (!username || !password) {
    req.flash("error", "Username and password are required");
    return res.redirect("/admin");
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.flash("error", "Username already exists. Please choose another.");
      return res.redirect("/admin");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      isAdmin: isAdmin === "true",
    });

    await newUser.save();

    req.flash("success", "User added successfully");
    res.redirect("/admin");
  } catch (error) {
    console.error("Error adding user:", error);
    req.flash("error", "An error occurred while adding the user.");
    res.redirect("/admin");
  }
});

app.post("/admin/edit/:id", async (req, res) => {
  const { id } = req.params;
  const { username, isAdmin } = req.body;
  try {
    await User.findByIdAndUpdate(id, {
      username,
      isAdmin: isAdmin === "true",
    });
    res.sendStatus(200);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/admin/delete/:id", async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect("/admin");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/search-news", isAuthenticated, async (req, res) => {
  const query = req.query.query || "default"; // Default value for query if undefined
  try {
    console.log("Searching news for query:", query);

    const response = await axios.get(
      `https://newsapi.org/v2/everything?q=${query}&apiKey=${process.env.NEWS_API_KEY}`,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        },
      }
    );

    console.log(
      "Primary API response received:",
      response.data.articles.length,
      "articles."
    );

    // Log the query in history
    await History.create({
      userId: req.session.user._id,
      action: "Searched news articles",
      input: query,
    });

    res.render("api1", { articles: response.data.articles });
  } catch (error) {
    console.error("Primary API failed. Trying fallback API...", error.message);

    try {
      const fallbackResponse = await axios.get(
        `https://newsdata.io/api/1/news?apikey=${process.env.SECOND_NEWS_API_KEY}&q=${query}`
      );

      console.log(
        "Fallback API response received:",
        fallbackResponse.data.results.length,
        "articles."
      );

      // Filter and map the articles to the desired structure
      const articles = fallbackResponse.data.results
        .filter((article) => article.language === "en") // Ensure only English articles are included
        .map((article) => ({
          title: article.title,
          description: article.description || "No description available.",
          url: article.link,
          publishedAt: article.pubDate,
          source: { name: article.source_id || "Unknown Source" },
        }));

      // Log the query in history
      await History.create({
        userId: req.session.user._id,
        action: "Searched news articles using fallback API",
        input: query,
      });

      res.render("api1", { articles });
    } catch (fallbackError) {
      console.error("Both APIs failed:", fallbackError.message);
      res.status(500).send("Error fetching news articles");
    }
  }
});

app.get("/api1", isAuthenticated, async (req, res) => {
  const query = "default"; // Default query for top headlines
  try {
    console.log("Fetching top headlines...");

    const response = await axios.get(
      `https://newsapi.org/v2/top-headlines?country=us&apiKey=${process.env.NEWS_API_KEY}`,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        },
      }
    );

    console.log(
      "Primary API response received:",
      response.data.articles.length,
      "articles."
    );

    const userId = req.session.user._id;

    // Save articles in the database
    for (const article of response.data.articles) {
      await API1.create({
        title: article.title,
        description: article.description,
        url: article.url,
        publishedAt: article.publishedAt,
        source: article.source.name,
        userId,
      });
    }

    // Log the action in history
    await History.create({
      userId,
      action: "Fetched top headlines from API1",
    });

    res.render("api1", { articles: response.data.articles });
  } catch (error) {
    console.error("Primary API failed. Trying fallback API...", error.message);

    try {
      const fallbackResponse = await axios.get(
        `https://newsdata.io/api/1/news?apikey=${process.env.SECOND_NEWS_API_KEY}&q=${query}`
      );

      console.log(
        "Fallback API response received:",
        fallbackResponse.data.results.length,
        "articles."
      );

      const userId = req.session.user._id;

      // Filter and map the articles to the desired structure
      const articles = fallbackResponse.data.results
        .filter((article) => article.language === "en") // Ensure only English articles are included
        .map((article) => ({
          title: article.title,
          description: article.description || "No description available.",
          url: article.link,
          publishedAt: article.pubDate,
          source: { name: article.source_id || "Unknown Source" },
        }));

      // Save articles in the database
      for (const article of articles) {
        await API1.create({
          title: article.title,
          description: article.description,
          url: article.url,
          publishedAt: article.publishedAt,
          source: article.source.name,
          userId,
        });
      }

      // Log the action in history
      await History.create({
        userId,
        action: "Fetched top headlines from fallback API",
      });

      res.render("api1", { articles });
    } catch (fallbackError) {
      console.error("Both APIs failed:", fallbackError.message);
      res.status(500).send("Error fetching news articles");
    }
  }
});

app.get("/api2", isAuthenticated, (req, res) => {
  res.render("api2", { quotes: [] });
});

app.get("/search-quotes", isAuthenticated, async (req, res) => {
  const query = req.query.query;
  try {
    const https = require("https");
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });

    const response = await axios.get(
      `https://api.quotable.io/search/quotes?query=${query}`,
      { httpsAgent }
    );

    await History.create({
      userId: req.session.user._id,
      action: "Searched for quotes",
      input: query,
    });

    res.render("api2", { quotes: response.data.results });
  } catch (error) {
    console.error("Error fetching quotes:", error);
    res.status(500).send("Error fetching quotes");
  }
});

app.use(express.static(path.join(__dirname, "public")));
// Start the server
app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}`)
);

module.exports = { User };
