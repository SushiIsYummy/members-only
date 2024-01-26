function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect('/sign-in');
  }
}

module.exports = {
  ensureAuthenticated,
};
