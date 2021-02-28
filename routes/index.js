var express = require('express');
var router = express.Router();
var jwt = require('jsonwebtoken');
var secretKey = require('../config/keys').secretKey;

const { check, validationResult }  = require('express-validator');
const passport = require('passport');
const passportLocal = require('passport-local');
const Auth = require('./users');

// passport.use(new passportLocal(Auth.authenticate()));
passport.use(Auth.createStrategy());

/* GET home page. */
router.get('/', function(req, res, next) {
  let messages = req.flash('msg');
  res.render('index', {messages});
});

/* GET login page */
router.get('/login', (req, res, next) => {

  jwt.sign({data: 'Expample of JWT'}, secretKey, { expiresIn: 3600 }, (err, token) => {
    res.json({
      success: true,
      token
    });
});
});

/* GET profile page. */
router.get('/profile', verifyToken , function(req, res, next) {

  jwt.verify(req.token, secretKey, {expiresIn: '30s'}, (err, authData) => {
    if(err) res.sendStatus(403);
    else {
      res.json({
        success: true,
        authData
      });
    }
  });  
});

/* GET profile page. */
router.get('/profile/:id', isLoggedIn , function(req, res, next) {
       Auth.findOne({_id:req.params.id})
    .then( data => res.render('profile', {data}))
    .catch( err => res.send(err));
});
// router.get('/profile', isLoggedIn, function(req, res, next) {
//   res.send('Welcome to login. <a href="/logout">logout</a>');
// });

/* POST reset Page */
router.post('/resetPassword', isLoggedIn, function (req, res, next) {
    Auth.findOne({_id: req.user._id})
      .then(user => {
          user.setPassword(req.body.newPassword)
            .then(() => {
                user.save()
                  .then(renewPassword => {
                      res.json({message: 'Password Changed!', renewPassword})
                  }).catch(err => res.json(err));
            }).catch(err => res.json(err))
      }).catch(err => res.json(err));
});

/* POST forgot Page */
router.post('/forgotPassword', isLoggedIn, function (req, res, next) {
  Auth.findOne({_id: req.user._id})
    .then(user => {
        user.changePassword(req.body.oldPassword,req.body.newPassword)
          .then(() => {
              user.save()
                .then(renewPassword => {
                    res.json({message: 'Password Changed!', renewPassword})
                }).catch(err => res.json(err));
          }).catch(err => res.json(err))
    }).catch(err => res.json(err));
});

/* GET logout page. */
router.get('/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

// POST register page.
router.post('/register', [
  check('email').isEmail(),
  check('password').isLength({ min: 6 }).withMessage('password must not be empty and have atleat 6 characters'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('msg', errors.errors);
    res.redirect('/');
  }

  const newAuth = new Auth({
    email: req.body.email
  });

  Auth.register(newAuth, req.body.password)
    .then(user => {
        passport.authenticate('local')(req,res, function (){
          req.flash('msg', `${user.email} successfully registered.`);
          res.redirect('/');
        })
    })
    .catch( err => res.send(err));
})

// POST login page
router.post('/login',(req, res, next) => {
  passport.authenticate('local', function(err, user, info) {
    // if (err) { return next(err); }
    if (!user) { 
      req.flash('msg', info);
      return res.redirect('/'); }
    req.logIn(user, function(err) {
      if (err) { return next(err); }
      // console.log(req.session)
      // console.log(req.user)
      return res.redirect('/profile/' + user._id);
    });
  })(req, res, next);
  
});

// router.post('/login',
//   passport.authenticate('local'),
//   function(req, res) {
//     res.redirect('/profile/' + req.user._id);
//   });
// router.post('/login', passport.authenticate('local',{
//   successRedirect: '/profile',
//   failureRedirect: '/'
// }), (req, res, next)=>{});


function isLoggedIn(req, res, next){
  if(req.isAuthenticated()) return next();
  req.flash('msg', 'you are logged out, can not access.');
  res.redirect('/');
}

// Format of Token
// Authorization: Bearer <access_token>

function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  // console.log(req.headers)
  if(typeof bearerHeader !==  'undefined') {
    const bearer =  bearerHeader.split(' ');
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  }
  else {
    res.sendStatus(403);
  }
}


module.exports = router;
