//jshint esversion:6
require("dotenv").config();
// const md5= require("md5");  //used for requiring hashing for our passwords which hashes it saves as hash in our database
                            //so if the user tries to login then the password enterd by him is again converted to hash and then compared by the hash stored in database.
                            //the hash code for a particular letter or no remains the same.

const express= require("express");
const ejs = require("ejs");
const bodyParser= require("body-parser");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
const { config } = require("dotenv");
const bcrypt= require("bcrypt");
const saltRounds =10;
const passport=require("passport");
const session= require("express-session");
const passportLocalMongoose= require("passport-local-mongoose"); //passport-local is required for this so we dont need to declare it separartely.
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app= express();

mongoose.set('strictQuery', false);
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine', 'ejs');

app.use(session({
    secret: "Our little secret.",  //go to docs (taken from it.)   //Applications must initialize session support in order to make use of login sessions. 
                                   //In an Express app, session support is added by using express-session middleware.
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());  //docs
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");


const userSchema= new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


//encrypting our passwords

// const secret="Thisisourlittlesecret."; //as anybode can see our encrption key and use it to decrypt the password therefore we make a .env file which uses environment variables.
// userSchema.plugin(encrypt, {secret:secret, encryptedFields:["password"]});  //Plugins are a tool for reusing logic in multiple schemas. Suppose you have several models in your database and want to add a loadedAt property to each one.
                                                                            // Just create a plugin once and apply it to each Schema
//after making env file
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());                //To maintain a login session, Passport serializes and deserializes user information to and from the session. 

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
                                                 //The information that is stored is determined by the application, which supplies a serializeUser and a deserializeUser function.
                                                   //creates cookie containing the information of the browser.
                                                           //crushes or break the cookie if there is session end or logout

                                             

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
    res.render("home");
});

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req,res){
   User.find({"secret":{$ne:null}} , function(err, foundUser){
    if(err){
        console.log(err);
    }
    else{
        if(foundUser){
            res.render("secrets", {userswSecrets: foundUser});
        }
        
    }
   })
});

app.get("/logout", function(req,res, next){
    req.logout(function(err) {
        if (err) { return next(err); }
    res.redirect("/");
});
});

app.get("/auth/google", 
    passport.authenticate('google', {scope: ["profile"]})  //this makes a pop that allows user to signin their google account.
);

app.get("/auth/google/secrets", 
passport.authenticate('google', {failureRedirect: "/login"}),
function(req,res){
    //Succesful authenciation redirect to home.
    res.redirect("/secrets");
});

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});


app.post("/login", function(req,res){
 
    const user=new User({
        username: req.body.username,
        passowrd: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/register", function(req, res){

   User.register({username: req.body.username}, req.body.password, function(err, user){  //register is the function of passportlocalmongoose package
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
   })
});

app.post("/submit", function(req,res){
    const submittedSecret=req.body.secret;
 

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            foundUser.secret=submittedSecret;
            foundUser.save(function(){
                res.redirect("/secrets");
            });
        }
    });

});


//whenver server is restrted the cookies get deleted and the session gets restarted.

app.listen("3000", function(){
    console.log("Server running on port 3000.");
})
