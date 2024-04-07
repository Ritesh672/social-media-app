import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

// Define the app
const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

// Connecting the database with the app
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// GET request to render the home page of the website
app.get("/", (req, res) => {
    res.render("home.ejs");
});

// login request for the website
app.get("/login", (req, res) => {
    res.render("index.ejs");
});

// the get request so the user can directly go to profile after authenticating
app.get("/profile", (req, res) => {
    console.log(req.user);
    if (req.isAuthenticated()) {
        res.render("profile.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get("/auth/google/profile", passport.authenticate("google", {
    successRedirect: "/profile",
    failureRedirect: "/login"
}));

// The register route 
app.get("/register", (req, res) => {
    res.render("register.ejs");
});

// POST request for the register route
app.post("/register", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password) {
        return res.render("register.ejs", { msg: "Username and password are required" });
    }
    // try catch block to register the user and redirect to the profile page
    try {
        // Check if the user already exists
        const existUser = await db.query("SELECT username FROM users WHERE username = $1;", [username]);

        if (existUser.rows.length !== 0) {
            return res.render("register.ejs", { msg: "User already exists" });
        } //error if the same username 

        // Hash the password
        const hash = await bcrypt.hash(password, saltRounds);

        // Insert user data into the database
        const newUser = await db.query("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *;", [username, hash]);
        console.log(newUser.rows[0]);

        // redirecting the user to the login of the home page
        if (newUser.rows.length > 0) {
            const user = newUser.rows[0];   // the user data that the user enter 
            req.login(user, (err) => {   // the login and authentication of the user
                if (err) {
                    console.error("Error during login:", err);
                    return res.status(500).send("Error during login");
                }
                res.redirect("/profile");
            });
        }
    } catch (err) {
        console.error("Error while registering user:", err);
        res.status(500).send("Error while registering user");
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/login",
}));

passport.use("local", new Strategy(async function (username, password, cb) {
    try {
        // Query to select the hashed password from the database
        const userData = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        if (userData.rows.length > 0) {
            // Check if the user exists in the database
            const hashPassword = userData.rows[0].password;

            // Use bcrypt to compare the provided password with the hashed password
            const match = await bcrypt.compare(password, hashPassword);
            if (match) {
                // If passwords match, return the user
                return cb(null, userData.rows[0]);
            } else {
                // If passwords don't match, return false
                return cb(null, false);
            }
        } else {
            // If user is not found in the database, return false
            return cb(null, false);
        }
    } catch (err) {
        // Handle errors
        console.error("Error during login:", err);
        return cb(err);
    }
}));

// Configure Google Strategy
passport.use("google", new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/profile",
},
    async (accessToken, refreshToken, profile, cb) => {
        // Google authentication logic
        console.log(profile);
        // You need to implement saving or retrieving user from the database based on 'profile' data.
        // This function should call 'cb(null, user)' if authentication succeeds or 'cb(err)' if it fails.
        try {
            const result = await db.query("SELECT * FROM users WHERE username = $1", [profile.email]);
            if (result.rows.length === 0) {
                const newUser = await db.query("INSERT INTO users (username, password) VALUES ($1, $2);", [profile.email, "google"]);
                cb(null, newUser.rows[0]);
            } else {
                // already existing user
                cb(null, result.rows[0])
            }
        } catch (err) {
            cb(err)
        }
    }
));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
