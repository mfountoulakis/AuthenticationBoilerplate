const passport = require('passport');
const ExtractJwt = require('passport-jwt').ExtractJwt;
const JwtStrategy = require('passport-jwt').Strategy;
const LocalStrategy = require('passport-local');

const User = require('../models/user');
const config = require('../config');

var localOptions = {
  usernameField: 'email'
}

var localStrategy = passport.use(new LocalStrategy(localOptions, function(email, password, done) {
  User.findOne({ email: email }, function (err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }
    user.comparePassword(password, function(err, isMatch){
      if (err) { return done(err) }
      if (!isMatch) { return done(null, false) }
      return done(null, user)
    })
  });
}));

var jwtOptions = {
  secretOrKey: config.secret,
  jwtFromRequest: ExtractJwt.fromHeader('authorization')
}

var jwtStrategy = passport.use(new JwtStrategy(jwtOptions, function(jwt_payload, done) {
  User.findById(jwt_payload.sub, function(err, user){
    if (err) {
      return done(err, false)
    }
    if (user){
      done(null, user);
    } else {
      done(null, false);
    }
  });
}));
