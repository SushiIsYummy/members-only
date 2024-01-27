const createError = require('http-errors');
const express = require('express');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require('mongoose');
const passport = require('passport');
require('dotenv').config();
const indexRouter = require('./routes/index');
const passportConfig = require('./config/passport-config');
const homeRouter = require('./routes/home');

// Connect to MongoDB using Mongoose
mongoose.connect(process.env.MONGODB_URI);

// Mongoose connection event handlers
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));
passportConfig(passport);
app.use(passport.initialize());
app.use(passport.session());

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to set authentication status variable
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated();
  if (req.isAuthenticated()) {
    res.locals.firstName = req.user.first_name;
    res.locals.lastName = req.user.first_name;
  }
  next();
});

app.use('/', indexRouter);
app.use('/home', homeRouter);

// catch 404 and forward to error handler
// app.use(function (req, res, next) {
//   next(createError(404));
// });

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
