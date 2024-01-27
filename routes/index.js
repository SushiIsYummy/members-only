const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const User = require('../models/user');
const Message = require('../models/message');
const { ensureAuthenticated } = require('../middlewares/authMiddleware');
const { DateTime } = require('luxon');
const _ = require('lodash');

router.get('/', [
  asyncHandler(async (req, res, next) => {
    res.redirect('/message-board');
  }),
]);

router.get('/home', [
  ensureAuthenticated,
  asyncHandler(async (req, res, next) => {
    const membershipStatus = req.user.membership_status;
    const memberMsg = `Membership status: ${_.capitalize(membershipStatus)}`;
    res.render('home', {
      adminPassword: '',
      memberPassword: '',
      wrongAdminPasswordMsg: false,
      wrongMemberPasswordMsg: false,
      memberMsg: memberMsg,
    });
  }),
]);

router.post('/home', [
  ensureAuthenticated,
  asyncHandler(async (req, res, next) => {
    const submittedMemberForm =
      req.body.member_form === 'Submit' ? true : false;
    const submittedAdminForm = req.body.admin_form === 'Submit' ? true : false;
    const adminPassword = req.body.admin_password;
    const memberPassword = req.body.member_password;
    const membershipStatus = req.user.membership_status;
    const memberMsg = `Membership status: ${_.capitalize(membershipStatus)}`;
    if (submittedAdminForm && adminPassword === process.env.ADMIN_PASSWORD) {
      await User.findByIdAndUpdate(req.user._id, {
        $set: { membership_status: 'admin' },
      });
      res.redirect('/home');
    }
    if (submittedMemberForm && memberPassword === process.env.MEMBER_PASSWORD) {
      await User.findByIdAndUpdate(req.user._id, {
        $set: { membership_status: 'member' },
      });
      res.redirect('/home');
    }
    res.render('home', {
      adminPassword: adminPassword,
      memberPassword: memberPassword,
      wrongAdminPasswordMsg:
        (req.body.admin_wrong_password === 'true' ||
          submittedAdminForm === true) === true
          ? true
          : false,
      wrongMemberPasswordMsg:
        (req.body.member_wrong_password === 'true' ||
          submittedMemberForm === true) === true
          ? true
          : false,
      memberMsg: memberMsg,
    });
  }),
]);

router.get('/sign-in', [
  asyncHandler(async (req, res, next) => {
    if (req.isAuthenticated()) {
      res.redirect('/home');
    } else {
      res.render('sign-in-form', { username: '', password: '', errorMsg: '' });
    }
  }),
]);

router.post('/sign-in', [
  function (req, res, next) {
    passport.authenticate('local', function (err, user, info) {
      if (err) {
        return next(err);
      }
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
        return res.redirect('/home');
      });
    })(req, res, next);
  },
]);

router.get('/register', [
  asyncHandler(async (req, res, next) => {
    res.render('register-form', {
      errors: [],
      firstNameRegister: '',
      lastNameRegister: '',
      username: '',
      password: '',
      confirmPassword: '',
    });
  }),
]);

router.post('/register', [
  body('first_name')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('First name must be specified.'),
  body('last_name')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('Last name must be specified.'),
  body('username')
    .custom((username) => !/\s/.test(username))
    .withMessage('No spaces are allowed in the username')
    .custom(async (username) => {
      const existingUser = await User.findOne({ username: username });
      if (existingUser) {
        errors.errors.push({
          msg: `The username is already taken.`,
        });
        return false;
      }
      return true;
    })
    .withMessage('The username is already taken.')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage('Username must be specified.'),
  // TODO: Password input currently has no strict requirements.
  // Consider adding password strength validation rules in the future if needed.
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
      res.render('register-form', {
        firstNameRegister: req.body.first_name,
        lastNameRegister: req.body.last_name,
        username: req.body.username,
        password: req.body.password,
        confirmPassword: req.body.confirm_password,
        errors: errors.array(),
      });
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
        res.redirect('/sign-in');
      });
    } catch (err) {
      return next(err);
    }
  }),
]);

router.get('/message-board', [
  asyncHandler(async (req, res, next) => {
    const allMessages = await Message.find({})
      .populate({
        path: 'user',
        select: 'username',
      })
      .exec();
    allMessages.map((message) => {
      message.timestamp = DateTime.fromISO(message.timestamp).toLocaleString(
        DateTime.DATETIME_MED
      );

      // message is created by the user
      if (req?.user?._id.toString() === message?.user?._id.toString()) {
        message.isUsers = true;
      }
    });
    res.render('message-board', {
      messages: allMessages,
      isMember: req.user?.membership_status === 'member',
      isAdmin: req.user?.membership_status === 'admin',
    });
  }),
]);

router.post('/delete-message', [
  asyncHandler(async (req, res, next) => {
    await Message.findByIdAndDelete(req.body.delete_message);
    res.redirect('/message-board');
  }),
]);

router.get('/sign-out', function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect('/sign-in');
  });
});

module.exports = router;
