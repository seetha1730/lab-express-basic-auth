const router = require("express").Router();
const bcryptjs = require('bcryptjs');
const User = require('../models/User.model');
const saltRounds = 10;

/* GET signup page */
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post('/signup', (req, res, next) => {
   
    const { username, email, password } = req.body;
   
    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
          
          username,
          email,
          passwordHash: hashedPassword
        });
      })
      .then(userFromDB => {
        console.log('Newly created user is: ', userFromDB);
        res.redirect('/userProfile');
      })
      .catch(error => next(error));
  });
  router.get('/userProfile', (req, res) => res.render('users/user-profile'));
module.exports = router;
