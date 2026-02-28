require('dotenv').config();
const { i18next, middleware } = require("./public/javascripts/i18n.js");
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var sessions = require('express-session');
var logger = require('morgan');
var crypto = require('crypto');
var csurf = require('csurf');

var index = require('./routes/index');
var optionsManagement = require('./routes/options.js');
var login = require('./routes/login');
var random = require('./routes/random');
var recovery = require('./routes/recovery.js');
var signUp = require('./routes/signup.js');
var generator = require('./public/javascripts/generator.js');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(sessions({
    secret: crypto.randomBytes(20).toString("hex"),
    saveUninitialized: true,
    resave: false
}));
app.use(middleware.handle(i18next));
/*var csfrPath = [
  '/index',
  '/options/editPwd',
  '/options/deleteAccount',
  '/options/securityManagement',
  '/options/editPin',
  '/options/resetPin',
  '/options/editEmail'
];
app.use(function (req, res, next) {
  if (csfrPath.indexOf(req.path) !== -1)
    csurf({ cookie: true })(req, res, next);
  else
    next();
});
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)
  console.log('Bad CSRF token');
  res.redirect(req.path);
})*/

app.use('/', index);
app.use('/options', optionsManagement);
app.use('/index', index);
app.use('/login', login);
app.use('/random', random);
app.use('/recovery', recovery);
app.use('/signup', signUp);
app.use('/generator', generator);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
    next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    return res.render('error');
});

module.exports = app;