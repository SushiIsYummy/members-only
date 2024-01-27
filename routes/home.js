const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { DateTime } = require('luxon');
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const User = require('../models/user');
const Message = require('../models/message');
const { ensureAuthenticated } = require('../middlewares/authMiddleware');

router.get('/new-message', [
  ensureAuthenticated,
  asyncHandler(async (req, res, next) => {
    res.render('new-message-form');
  }),
]);

router.post('/new-message', [
  ensureAuthenticated,
  body('title').trim().isLength({ min: 1 }).escape(),
  body('text').trim().isLength({ min: 1 }).escape(),
  asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('new-message-form');
      return;
    }
    const message = new Message({
      title: req.body.title,
      text: req.body.text,
      timestamp: DateTime.utc().toISO(),
      user: req.user._id,
    });
    const result = await message.save();
    res.redirect('/message-board');
  }),
]);

module.exports = router;
