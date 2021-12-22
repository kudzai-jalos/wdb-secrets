//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// mongoose init
const uri = "mongodb://localhost:27017/userDB";
mongoose.connect(uri).catch((err) => {
  console.log(err);
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const secret = process.env.SECRET;

userSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});

const User = mongoose.model("User", userSchema);
// ////Root////
app.route("/").get((req, res) => {
  res.render("home");
});

// ////Login////
app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post( async (req,res)=>{
      const userName = req.body.username;
      const password = req.body.password;

      const user= await User.findOne({email:userName},(err)=>{
        if (err){
            console.log(err);
        }
      }).clone().exec();
      
      if (user && user.password===password){
          res.render('secrets');
      } else {
          res.send('Incorrect username or password');
      }
  });

// ////register////
app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    const newUser = new User({
      email: req.body.username,
      password: req.body.password,
    });

    newUser.save((err) => {
      if (err) console.log(err);
      else res.render("secrets");
    });
  });

app.listen(3000, () => {
  console.log("Server started on port 3000");
});

// Level 1 security
// email and password

// Level 2 Security
// database encryption
