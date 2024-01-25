const express = require('express');
const router = express.Router();
const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');

router.get('/', [
  asyncHandler(async (req, res, next) => {
    res.render('login-form');
  }),
]);

router.get('/sign-up', [
  asyncHandler(async (req, res, next) => {
    res.render('sign-up-form');
  }),
]);

module.exports = router;
