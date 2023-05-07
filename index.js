
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

app.set("view engine", "ejs");

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
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}
function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

app.get("/", (req, res) => {  

  res.render("index", {username: req.session.username});
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

    res.render("about", {color: color});
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    res.render("contact", {missing: missingEmail});
});



app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.res.render("submitEmail", { email: email });
    }
});


app.get('/createUser', (req,res) => {
    res.render("createUser");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  // if (!username) {
  //   res.send("All fields are required. <a href='/createUser'>Try again</a>");
  // } else if (!email) {
  //   res.send("All fields are required. <a href='/createUser'>Try again</a>");
  // } else if (!password) {
  //   res.send("All fields are required. <a href='/createUser'>Try again</a>");
  // } else {
    const schema = Joi.object({
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate(req.body);

    if (validationResult.error != null) {
      console.log(validationResult.error);
      req.redirect("/createUser")
      return
    } 
      // const salt = await bcrypt.genSalt(saltRounds);
      const hashedPassword = await bcrypt.hash(password, saltRounds);


      await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        user_type: "user",
      });
      console.log("user inserted")
      var html = "successfully created user";
      res.render("submitUser", { html: html });
    }
  
);


app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  // Find the user in the database using email
  // const user = await userCollection.findOne({ username: username });
  // if (!user) {
  //   return res.status(400).send("user not found");
  // }

  // // Compare the password with the hashed password using bcrypt
  // const passwordMatch = await bcrypt.compare(password, user.password);
  // if (!passwordMatch) {
  //   return res.status(400).send("invalid password");
  // }

  // // Store the user's name in the session and redirect to members page
  // req.session.username = user.username;
  // console.log("logged in as " + req.session.username);
  // res.redirect("/members");
  const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}


  // const oneHour = 60 * 60 * 1000;
  // req.session.timer = setTimeout(() => {
  //   req.session.destroy((err) => {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       console.log("session destroyed successfully");
  //     }
  //   });
  // }, oneHour);
});

app.use("/loggedin", sessionValidation);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin", {username: req.session.username});
});

app.get("/loggedin/info", (req, res) => {
  res.render("loggedin-info");
});

app.get("/cats", (req, res) => {
  const name = req.session.username;

  if (!name) {
    res.redirect("/login");
    return;
  }
  else{
    res.render("cats");
  }

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
    res.render('loggedout')
  });

  // const randomImage = Math.floor(Math.random() * 3) + 1;
  // res.send(`
  //   <h1>Hello, ${name}!</h1>
  //   <img src="/${randomImage}.gif" alt="random image">
  //   <a href="/logout">Logout</a>
  // `);
  app.get("/cat/:id", (req, res) => {
    var cat = req.params.id;
    res.render("cat", { cat: cat });
  });

});

// app.get("/cats", (req, res) => {
//   res.render("cats");
// })

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.render("loggedout");
});
app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    // if (cat == 1) {
    //     res.send("Fluffy: <img src='/1.gif' style='width:250px;'>");
    // }
    // else if (cat == 2) {
    //     res.send("Socks: <img src='/2.gif' style='width:250px;'>");
    // }
    // else if (cat == 3) {
    //     res.send("Tiger: <img src='/3.gif' style='width:250px;'>");
    // }
    // else {
    //     res.send("Invalid cat id: "+cat);
    // }
    res.render("cat", {cat: cat});
});
app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  console.log("admin page")
  const users = await userCollection
    .find()
    .project({ username: 1, _id: 1 })
    .toArray();

  res.render("admin", { users: users });
  
});
app.post("/promote", adminAuthorization, async (req, res) => {
  console.log("body: ", req.body);
  const nameSelected = req.body.nameSelected;
  const result = await userCollection.updateOne(
    { username: nameSelected },
    { $set: { user_type: "admin" } }
  );
  console.log("result: ", result);

  res.redirect("/admin");
});
app.post("/demote", adminAuthorization, async (req, res) => {
  console.log("body: ", req.body);
  const nameSelected = req.body.nameSelected;
  const result = await userCollection.updateOne(
    { username: nameSelected },
    { $set: { user_type: "user" } }
  );
  console.log("result: ", result);
  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 