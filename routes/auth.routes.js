const express = require('express');
const router = express.Router();
// Require user model
const User = require('../models/User.model');
// Add bcrypt to encrypt passwords
const bcrypt = require('bcrypt');
// Add passport
const passport = require('passport')



const ensureLogin = require('connect-ensure-login');

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('auth/private', { user: req.user });
});


//Signup Stuff 

router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;
  if (password.length < 8) {
    res.render('auth/signup', { message: 'Your password must be 8 characters minimum' });
    return;
  }
  if (username === '') {
    res.render('auth/signup', { message: 'Your username cannot be empty' });
    return;
  }
  
  User.findOne({ username: username }).then(found => {
    if (found !== null) {
      res.render('signup', { message: 'Username already exists!' });
    } else {
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);
  
      User.create({ username: username, password: hash })
        .then(userDB => {
          res.redirect('auth/login');
        })
        .catch(err => {
          next(err);
        });
    }
  })
  });

//Login Stuff
router.get('/login', (req, res) => {
  res.render('auth/login');
});

router.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/private-page');
  });

module.exports = router;
