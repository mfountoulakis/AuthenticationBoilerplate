const passport = require('passport');

const AuthenticationController = require('../controllers/authentication_controller')
const PassportService = require('./passport');

var requireAuth = passport.authenticate('jwt', {session: false});
var requireLogin = passport.authenticate('local', {session: false});

var router = require('express').Router();

// Auth Routes
// -----------------------------------------------------------------------------
router.route('/signup')
  .post(AuthenticationController.signup)

router.route('/signin')
  .post([requireLogin, AuthenticationController.signin])


// SECRET
// -----------------------------------------------------------------------------
router.route('/protected')
  .get(requireAuth, protected)

module.exports = router;
