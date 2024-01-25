const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const User = require('../models/user');

router.get('/', [
  asyncHandler(async (req, res, next) => {
    res.send('You have successfully signed in.');
  }),
]);

router.get('/home', [
  asyncHandler(async (req, res, next) => {
    res.send('You have successfully signed in.');
  }),
]);

router.get('/sign-in', [
  asyncHandler(async (req, res, next) => {
    res.render('sign-in-form', { username: '', password: '', errorMsg: '' });
  }),
]);

router.post('/sign-in', [
  function (req, res, next) {
    passport.authenticate('local', function (err, user, info) {
      if (err) {
        return next(err);
      }
      console.log(user);
      console.log(info);
      if (!user) {
        return res.render('sign-in-form', {
          username: req.body.username,
          password: req.body.password,
          errorMsg: 'Your username or password is incorrect.',
        });
      }
      req.logIn(user, function (err) {
        if (err) {
          return next(err);
        }
        return res.send(
          `You have successfully logged in, ${user.first_name} ${user.last_name}.`
        );
        // return res.redirect('/users/' + user.username);
      });
    })(req, res, next);
  },
  // asyncHandler(async (req, res, next) => {
  //   res.render('sign-in-form', {
  //     username: req.body.username,
  //     password: req.body.password,
  //     errorMsg: 'Your account name or password is incorrect.',
  //   });
  // }),
]);

router.get('/register', [
  asyncHandler(async (req, res, next) => {
    res.render('register-form', { errors: [] });
  }),
]);

router.post('/register', [
  body('first_name')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('First name must be specified.')
    .isAlphanumeric()
    .withMessage('First name has non-alphanumeric characters.'),
  body('last_name')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('Last name must be specified.')
    .isAlphanumeric()
    .withMessage('Last name has non-alphanumeric characters.'),
  body('username')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('Username must be specified.'),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password must be specified'),
  body('confirm_password')
    .custom((value, { req }) => {
      return value === req.body.password;
    })
    .withMessage('Passwords do not match'),
  asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('register-form', { errors: errors.array() });
      return;
    }
    try {
      bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
        if (err) {
          throw new Error();
        }
        // store hashedPassword in DB
        const user = new User({
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          username: req.body.username,
          password: hashedPassword,
        });
        const result = await user.save();
        res.redirect('/');
      });
    } catch (err) {
      return next(err);
    }
  }),
]);

module.exports = router;
