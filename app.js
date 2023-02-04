//jshint esversion:6

require('dotenv').config();

const bcrypt = require('bcrypt');
const saltRounds = 10;

const express = require('express');

const bodyParser = require('body-parser');

const ejs = require('ejs');

const app = express();

const mongoose = require('mongoose');

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});

mongoose.set('strictQuery', true);

app.use(express.static('public'));

app.set('view engine','ejs');

app.use(bodyParser.urlencoded({extended:true}));

const userSchema = new mongoose.Schema ({
    email:String,
    password:String
});

const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res) {
    res.render("home");
});

app.get("/login",function(req,res) {
    res.render("login");
});

app.get("/register",function(req,res) {
    res.render("register");
});

app.post("/register",function(req,res) {

///////////////*********************  Creating   the   hash   function *******************/////////////////
    
bcrypt.hash(req.body.password,saltRounds,function(err,hash) {
        const newUser = new User ({
            email: req.body.username,
            password: hash
        });
        newUser.save(function(err) {
            if (err) {
                res.send(err)
            }else{
                res.render('secrets');
            }
        });
    });
    
});

app.post("/login",function(req,res) {
    const username = req.body.username;
    const password = req.body.password;
    
    User.findOne({email:username},function(err,foundUser) {
        if (err){
            console.log(err);
        }else{
            if (foundUser){
                bcrypt.compare(password,foundUser.password,function(err,result) {
                    if (result === true) {
                        res.render("secrets");
                    }
                });
            }
        }
    });
});


app.listen(3000,function(){
    console.log("App start listening on port 3000")
});