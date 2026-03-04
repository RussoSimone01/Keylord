import 'dotenv/config';
import i18next from "./public/javascripts/i18n.js";
import createError from 'http-errors';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import cookieParser from 'cookie-parser';
import sessions from 'express-session';
import logger from 'morgan';
import { randomBytes } from 'crypto';
import csurf from 'csurf';

import index from './routes/index.js';
import optionsManagement from './routes/options.js';
import login from './routes/login.js';
import random from './routes/random.js';
import recovery from './routes/recovery.js';
import signUp from './routes/signup.js';
import generator from './public/javascripts/generator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

var app = express();

// view engine setup
app.set('views', join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(join(__dirname, 'public')));
app.use(sessions({
    secret: randomBytes(20).toString("hex"),
    saveUninitialized: true,
    resave: false
}));
app.use(i18next.middleware.handle(i18next.i18next));
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

export default app;