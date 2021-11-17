var express = require('express');
var jwt = require('jsonwebtoken');
var sqlite = require('sqlite3');
var crypto = require('crypto');

//const KEY = "m yincredibl y(!!1!11!)<'SECRET>)Key'!";
const KEY = "add&*23salt56and$storn!the#@$database!";

var db = new sqlite.Database("users.sqlite3");

var app = express();


app.post('/signup', express.urlencoded(), function(req, res) {
    console.log(req.body);
  // in a production environment you would ideally add salt and store that in the database as well
  // or even use bcrypt instead of sha256. No need for external libs with sha256 though
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  db.get("SELECT * FROM users WHERE username = ?", [req.body.username], function(err, row) {
    if(row != undefined ) {
      console.error("can't create user " + req.body.username);
      res.status(409);
      res.send("An user with that username already exists");
    } else {
      console.log("Can create user " + req.body.username);
      db.run('INSERT INTO users(username, password) VALUES (?, ?)', [req.body.username, password]);
      res.status(201);
      res.json({'message':'Success'});
    }
  });
});

app.post('/login', express.urlencoded(), function(req, res) {
  console.log(req.body);
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  db.get("SELECT * FROM users WHERE (username, password) = (?, ?)", [req.body.username, password], function(err, row) {
    if(row != undefined ) {
      var payload = {
        username: req.body.username,
      };

      var token = jwt.sign(payload, KEY, {algorithm: 'HS256', expiresIn: "15d"});
      console.log("Success");
      res.status(200);
      res.json({'token':token});
    } else {
      console.error("Failure");
      res.status(401)
      res.send("There's no user matching that");
    }
  });
});

app.get('/data', function(req, res) {
  var str = req.get('Authorization');
  try {
    jwt.verify(str, KEY, {algorithm: 'HS256'});
    res.send("Very Secret Data");
  } catch {
    res.status(401);
    res.send("Bad Token");
  }

});

//這是網站的根目錄首頁，也是homepage
app.get("/", (req, res) => {
  console.log(__dirname);
  console.log(__filename);
  res.sendFile(__dirname + "/index.html");
});
app.post("/logout", (req, res) => {
  console.log('logout called');
  res.json({msg:"System logouted!"});
});  

//JSONP Get Request
app.get('/endpointJSONP', function(req, res){

  //LOG  
  console.log('JSONP response');
  console.log(req.query);
  //JSONP Response (doc: http://expressjs.com/api.html#res.jsonp) 
  res.jsonp(req.query) 
});


let port = process.env.PORT || 3000;
app.listen(port, function () {
    return console.log("Started user authentication server listening on port " + port);
});