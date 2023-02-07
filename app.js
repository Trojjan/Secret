//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const mongoose = require('mongoose');
const { x64 } = require('crypto-js');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;
mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});

mongoose.set('strictQuery', true);

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine','ejs');
app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema ({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    username: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    // passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "https://127.0.0.1:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id,username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res) {
    res.render("home");
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get("/auth/google",
    passport.authenticate('google', { scope: ["email","profile"] })
);


app.get('/auth/google/secrets',
passport.authenticate('google',{failureRedirect:'/login'}),
function(req,res) {
    res.redirect('/secrets');
}
);

app.get("/login",function(req,res) {
    res.render("login");
});

app.get("/register",function(req,res) {
    res.render("register");
});

app.get('/secrets',function(req,res) {
    if (req.isAuthenticated()) {
        res.render('secrets');
    } else {
        res.redirect('login');
    }
});

app.get("/logout", function(req, res){
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
    
});

app.post("/register",function(req,res) {
    User.register({username:req.body.username},req.body.password,function(err,user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate('local')(req,res,function () {
                res.redirect('/secrets');
            })
        }
    });
});

passport.use(User.createStrategy());

app.post("/login",function(req,res) {
   const user = new User({
    username: req.body.username,
    password: req.body.password
   });
   req.login(user,function(err) {
    if (err) {
        console.log(err);
    } else {
        passport.authenticate('local')(req,res,function () {
            res.redirect('/secrets');
    });
    }
   });
});


app.listen(3000,function(){
    console.log("App start listening on port 3000")
});