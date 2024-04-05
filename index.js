import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

// Define the app
const app = express();
const port = 3000;
const saltRounds = 10;
env.config()

// Connecting the database with the app
const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "social",
    password: "Ritesh222@",
    port: "5432"
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Session middleware
app.use(session({
    secret: "TOPSECRETWORD", // the key to store the user login info
    resave: false, // this is used to store the data on the database here is false cause we are not saving it 
    saveUninitialized: true, // to store in the server memory
    cookie : {
        maxAge : 1000 * 60 * 60 * 24
    }
}));

// Passport after the session middleware
app.use(passport.initialize());
app.use(passport.session());

// GET request to render the home page of the website
app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("index.ejs");
});

app.get("/profile", (req, res) => {
    console.log(req.user);
    if (req.isAuthenticated()) {
        res.render("profile.ejs");
    } else {
        res.redirect("/login");
    }
});

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

    try {
        // Check if the user already exists
        const existUser = await db.query("SELECT username FROM users WHERE username = $1;", [username]);

        if (existUser.rows.length !== 0) {
            return res.render("register.ejs", { msg: "User already exists" });
        }

        // Hash the password
        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err) {
                console.error("Error while generating hash value:", err);
                return res.status(500).send("Error while generating hash value");
            }
            try {
                // Insert user data into the database
                const  newUser =  await db.query ( "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *;", [username, hash]);

                console.log(newUser.rows[0]);


                if (newUser.rows.length > 0){
               
                    const user = newUser.rows[0];
                    req.login(user, (err)=>
                    {
                        console.log(err);
                        res.redirect("/profile");

                    });
                }



            } catch (err) {
                console.error("Error while inserting the user's data:", err);
                res.status(500).send("Error while inserting the user's data");
            }
        });
    } catch (err) {
        console.error("Error while handling the SQL request:", err);
        res.status(500).send("Error while handling the SQL request");
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/login",
}));

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        // Query to select the hashed password from the database
        const userData = await db.query("SELECT * FROM users WHERE username = $1", [username]);

        if (userData.rows.length > 0) {
            // Check if the user exists in the database
            const hashPassword = userData.rows[0].password;

            // Use bcrypt to compare the provided password with the hashed password
            bcrypt.compare(password, hashPassword, function (err, result) {
                if (err) {
                    // Handle error
                    return cb(err);
                }
                if (result) {
                    // If passwords match, return the user
                    return cb(null, userData.rows[0]);
                } else {
                    // If passwords don't match, return false
                    return cb(null, false);
                }
            });
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

passport.serializeUser((user, cb)=>
{
    cb(null, user);
});

passport.deserializeUser((user, cb)=>
{
    cb(null, user);
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
