
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT ||3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get("/", (req, res) => {
  if (!req.session.username) {
    res.send(`
      You are not logged in.
      <br><a href="/login">Login</a>
      <br><a href="/createUser">Create User</a>
    `);
  } else {
    res.send(`
      Hello, ${req.session.username}.
      <br><a href="/members">Members Area</a>
      <br><a href="/logout">Logout</a>
    `);
  }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Lulu</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='Enter your username'><br>
    <input name='email' type='email' placeholder='Enter your email'><br>
    <input name='password' type='password' placeholder='Enter your password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username) {
    res.send("All fields are required. <a href='/createUser'>Try again</a>");
  } else if (!email) {
    res.send("All fields are required. <a href='/createUser'>Try again</a>");
  } else if (!password) {
    res.send("All fields are required. <a href='/createUser'>Try again</a>");
  } else {
    const schema = Joi.object({
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate(req.body);

    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.send(
        `Invalid input: ${validationResult.error.details[0].message}. <a href='/createUser'>Try again</a>`
      );
    } else {
      const salt = await bcrypt.genSalt(saltRounds);
      const hashedPassword = await bcrypt.hash(password, salt);

      await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
      });

      res.send(
        `User ${username} has been created. <a href='/login'>Log in</a>`
      );
    }
  }
});


app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  // Find the user in the database using email
  const user = await userCollection.findOne({ email: email });
  if (!user) {
    return res.status(400).send("user not found");
  }

  // Compare the password with the hashed password using bcrypt
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(400).send("invalid password");
  }

  // Store the user's name in the session and redirect to members page
  req.session.username = user.username;
  console.log("logged in as " + req.session.username);
  res.redirect("/members");

  const oneHour = 60 * 60 * 1000;
  req.session.timer = setTimeout(() => {
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
      } else {
        console.log("session destroyed successfully");
      }
    });
  }, oneHour);
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});
app.get("/members", (req, res) => {
  const name = req.session.username;

  if (!name) {
    res.redirect("/");
    return;
  }

  const randomImage = Math.floor(Math.random() * 2) + 1;

  res.send(`
    <h1>Hello, ${name}!</h1>
    <img src="/${randomImage}.gif" alt="random image">
    <a href="/logout">Logout</a>
  `);
});

app.get("/logout", (req, res) => {
    clearTimeout(req.session.timer);
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 