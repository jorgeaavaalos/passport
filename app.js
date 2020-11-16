const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const hbs = require('express-handlebars');
const session = require('express-session');
const mysql = require("mysql");
const MySQLStore = require("express-mysql-session")(session);
require("dotenv").config();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;


const options = {
  connectionLimit: 100,
  host     : process.env.DB_HOST,
  user     : process.env.DB_USER,
  password : process.env.DB_PASS,
  database : process.env.DB_NAME
}

const connection = mysql.createPool(options);

const sessionStore = new MySQLStore(options);


const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.engine(
	"hbs",
	hbs({
		defaultLayout: 'layout',
		extname: ".hbs"
	})
);
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
	session({
		secret: process.env.SECRET_KEY,
		store: sessionStore,
		// secure: true, // requires an https connection
		resave: false,
		saveUninitialized: false,
		cookie: {
		  maxAge: 24 * 60 * 60 * 1000, // 24 horas más
		},
	})
);

passport.use(new LocalStrategy( {
    usernameField: 'username_login',
    passwordField: 'user_password_login'
  },
  function(username, password, cb) {
      
      connection.query("SELECT * FROM users WHERE username = ? AND user_password = ?", [username, password], function(err, results) {
        if(err) {
          return cb(err);
        }
        // Si el usuario no existe
        if(!results.length) {
          return cb(null, false);
        }

        // Si la contraseña es incorrecta
        if(results[0].user_password != password) {
          return cb(null, false);
        }

        // El usuario existe y la contraseña es correcta
        return cb(null, results[0]);
      })
}));

passport.serializeUser(function(user, cb) {
  cb(null, user.user_id);
});

passport.deserializeUser(function(id, cb) {
  connection.query("SELECT * FROM users WHERE user_id = ?", [id], function(err, results) {
    if(err) {
      return cb(err);
    }

    cb(null, results[0]);
  })
});

app.use(passport.initialize());
app.use(passport.session());

app.get('/', function(req, res) {
  console.log('User: ', req.user);
  console.log('Session: ', req.session);
  res.render('index', { title: 'Express', loggedIn: req.isAuthenticated() });
});

app.get('/login', function(req, res) {
  if(req.isAuthenticated()) {
    res.redirect('/user');
  } else {
    res.render('login', { title: 'Express' });
  }
});

app.get('/signup', function(req, res) {
  if(req.isAuthenticated()) {
    res.redirect('/user');
  } else {
    res.render('signup', { title: 'Express' });
  }
});

app.post('/signup', function(req, res) {
  console.log('Sign Up');
  let inserts = [req.body.username_signup, req.body.user_password_signup];
  let sql = "INSERT INTO users(username, user_password) VALUES(?,?);";
  const query = mysql.format(sql, inserts);
  connection.query(query, function(err, results) {
    if(err) {
      throw err;
    }
    console.log('Exito');
    res.redirect('/login');
  })
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure', successRedirect: '/user' }), function(err, req, res, next) {
  if(err) next(err);
});


app.get('/user', function(req, res) {
    if (req.isAuthenticated()) {
        console.log(req.user)
        res.render('user', { title: 'Express', username: req.user.username, password: req.user.user_password });
    } else {
        console.log('You are not authenticated');
        res.redirect('/login');
    }
});


app.get('/login-failure', (req, res) => {
  // res.send('You entered the wrong username or password.');
  console.log('Fallaste');
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('connect.sid');
  // req.logout();
  req.session.destroy(function(err) {
    if(err) {
      throw err;
    }
    // req.logout();
    res.redirect('/login');
  }); 
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

// connection.end();

module.exports = app;
