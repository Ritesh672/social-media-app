import express from "express"; // import express and neccessary module
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import axios from "axios";
import bcrypt, { hash } from "bcrypt";

//define the app
const app = express();
const port = 3000;
const saltRounds = 10;

// connectin the database with the app
const db = new pg.Client({
    user: "postgres",
    host : "localhost",
    database : "social",
    password: "Ritesh222@",
    port : "5432"
})

db.connect();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// the get request to render the home page of the website
app.get("/", (req, res)=>{
    res.render("index.ejs");
});


// the register route 
app.get("/register", (req, res)=>
{
    res.render("register.ejs");
});

//post request for the register route
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
                console.log("Error while generating hash value:", err);
                return res.status(500).send("Error while generating hash value");
            }

            try {
                // Insert user data into the database
                const input = await db.query("INSERT INTO users (username, password) VALUES ($1, $2);", [username, hash]);
                // Redirect to home page after successful registration
                res.render('home.ejs');
            } catch (err) {
                console.log("Error while inserting the user's data:", err);
                res.status(500).send("Error while inserting the user's data");
            }
        });
    } catch (err) {
        console.log("Error while handling the SQL request:", err);
        res.status(500).send("Error while handling the SQL request");
    }
});



app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // if not username or passowrd
        if (!username || !password) {
            return res.render("index.ejs", {msg : "Username and password required"});
        }
        
        // the query to select the hash password from the database
        const userData = await db.query("SELECT password FROM users WHERE username = $1", [username]);
        console.log(userData.rows[0]);

        // to check if the user exists in the database
        if (userData.rows.length === 0) {
            return res.render("index.ejs", {msg : "User does not exist"});
        }
        else{
            const hashPassword = userData.rows[0].password; // the hash password obtaine if the user exists in the database //

            // the bcrypt to encrypt the userpassword to check for the user password
            bcrypt.compare(password, hashPassword, (err, result)=>
            {
                // handle the error 
                if  (err) {
                    console.log("Error while encrypting the password", err);}
                else{
                    if (result){
                        res.render("home.ejs"); }
                    else {
                        res.render("login.ejs", {msg: "Incorrect password"});}
                }});  
        }
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).send("Internal server error.");
    }
});


app.listen(port, ()=>{
    console.log(`server running on port ${port}`);
});