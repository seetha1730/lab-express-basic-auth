const router = require("express").Router();
const bcryptjs = require("bcryptjs");
const User = require("../models/User.model");
const mongoose = require("mongoose");
const saltRounds = 10;
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');
/* GET signup page */
router.get("/signup", isLoggedOut,(req, res) => {
  res.render("auth/signup");
});

router.post("/signup", isLoggedOut,(req, res, next) => {
 
  const { username, email, password } = req.body;
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }
  // make sure users fill all mandatory fields:
  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
    });
    return;
  }
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        username,
        email,
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDB) => {
      console.log("Newly created user is: ", userFromDB);
      res.redirect("/userProfile");
    })
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
      } else if (error.code === 11000) {
 
        //console.log(" ");
 
        res.status(500).render('auth/signup', {
          // errorMessage: 'User not found and/or incorrect password.'
          errorMessage: "Username and email need to be unique. Either username or email is already used. "
        });
      } else {
        next(error);
      }
  }) 
});
//////////// L O G I N ///////////

// GET route ==> to display the login form to users
router.get('/login',isLoggedOut, (req, res) => res.render('auth/login'));
// POST login route ==> to process form data
router.post('/login',isLoggedOut, (req, res, next) => {
 // console.log('SESSION =====> ', req.session);
  const { email, password } = req.body;
 
 
  if (email === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, email and password to login.'
    });
    return;
  }
 
  User.findOne({ email })
    .then(user => {
     
      if (!user) {
      
        console.log("Email not registered. ");
        res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        // res.render('users/user-profile', { user });
      
       req.session.currentUser = user
       console.log(res.session)
       res.redirect('/userProfile')

      } else {
        console.log("Incorrect password. ");
        res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
      }
    })
    .catch(error => next(error));
});
 
router.get('/userProfile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.currentUser });
});

router.post('/logout', isLoggedIn, (req, res) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

///////main page//////

router.get('/main', isLoggedIn, (req, res) => {
  res.render('main', { userInSession: req.session.currentUser });
});

router.get('/private', isLoggedIn, (req, res) => {
  res.render('private', { userInSession: req.session.currentUser });
});

module.exports = router;
