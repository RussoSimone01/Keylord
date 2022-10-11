var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var sessions = require('express-session');
var logger = require('morgan');
var crypto = require('crypto');
var csurf = require('csurf');


var index = require('./routes/index');
var itGestione = require('./routes/it/gestione');
var itIndex = require('./routes/it/index');
var itLogin = require('./routes/it/login');
var itRandom = require('./routes/it/random');
var itRecupero = require('./routes/it/recupero');
var itRegistrazione = require('./routes/it/registrazione');
var enGestione = require('./routes/en/gestione');
var enIndex = require('./routes/en/index');
var enLogin = require('./routes/en/login');
var enRandom = require('./routes/en/random');
var enRecupero = require('./routes/en/recupero');
var enRegistrazione = require('./routes/en/registrazione');
var generatore = require('./public/javascripts/generatore');

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
/*var csfrPath = [
  '/it/index',
  '/en/index',
  '/it/gestione/cambia',
  '/en/management/change',
  '/it/gestione/elimina',
  '/en/management/delete',
  '/it/gestione/sicurezza',
  '/en/management/security',
  '/it/gestione/pin',
  '/en/management/pin',
  '/it/gestione/reset',
  '/en/management/reset',
  '/it/gestione/email',
  '/en/management/email'
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
app.use('/it/gestione', itGestione);
app.use('/it/index', itIndex);
app.use('/it/login', itLogin);
app.use('/it/random', itRandom);
app.use('/it/recupero', itRecupero);
app.use('/it/registrazione', itRegistrazione);
app.use('/en/management', enGestione);
app.use('/en/index', enIndex);
app.use('/en/login', enLogin);
app.use('/en/random', enRandom);
app.use('/en/recovery', enRecupero);
app.use('/en/registration', enRegistrazione);
app.use('/generatore', generatore);

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