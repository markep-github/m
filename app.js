var loggedInUser = "";
const express = require('express');
const fs = require('fs');
const app = express();
const path = require('path');
const logging = false;
const port = process.env.PORT || 3001;
const user = process.env.MONGOUSER || "Admin";
const password = process.env.MONGOPASSWORD || "Password";
const server = process.env.MONGOSERVER || "127.0.0.1";
const dbport = process.env.MONGOPORT || 27017;

if (user == null || user == "" || password == null || password == "")  {
    if (user == null || user == "") console.log("MongoDB username is not.");
    if (password == null || password == "") console.log("MongoDB password is not.");
    console.log("Aborting/Terminating application.");
    process.exitCode = 1;
    process.abort();
}


app.listen(port,() => {
    if (logging) console.log("Sever started at port "+port);
})

// Setup MongoDB database
const mongoose = require('mongoose');
const url = 'mongodb://'+user+':'+password+'@'+server+':'+dbport+'/';
const options = {
    ssl: false,
    readPreference: "primary",
    authSource: "admin",
    appname: "NodeJS-Login"
};
mongoose.connect(url,options,
    function() {
        if (logging) console.log("Connected to mongoDB")
    }
);

// Setup body parser
const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());

const User = require('./models/User');
const bcrypt = require('bcrypt');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;


const ejs = require('ejs');
app.set('view engine','ejs');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const uid = require('uid-safe');

passport.serializeUser(function(user,done){
    if (logging)  {
        console.log("USER: "+user);
        console.log("ID: "+user.id);
    }
    done(null,user.id);
});

passport.deserializeUser(function(id,done) {
    if (logging) console.log("ID: "+id);
    User.findById(id, function(error,user) {
        if (logging)  {
            console.log("USER: "+user);
            console.log("ERROR: "+error);
        }
        loggedInUser = user;
        done(error,user);
    });
});

passport.use(new LocalStrategy({
    usernameField:'userName',
    passwordField:'password'
    },
    function(username,password,done) {
        if (logging) console.log("USERNAME: "+username);
        User.findOne({
            userName:username
        },function(err,userData) {
            if (err) return done(err);
            if (!userData) return done(null, false);
            let passwordCheck = bcrypt.compareSync(password,userData.password);
            if (username === userData.userName && passwordCheck) {
                return done(null,userData);
            }
        });
    })
);

app.use(session({
    genid: function(req) {
        if (logging) console.log("Logged in user name: "+loggedInUser);
        return uid.sync(18)
    },
    store: new FileStore({retries:0}), 
    secret: 'x#jNwPD123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());


// setup style sheets, images and fonts
app.use('/images',express.static(__dirname + '/images'));
app.use('/css',express.static(__dirname + '/css'));
app.use('/fonts',express.static(__dirname + '/fonts'));

//const usersRoute = require('./routes/UserRoutes');
//app.use('/users',usersRoute);

//
// Routes
//
app.post('/user',(req,res) => {
    console.log("Creating user ");
    const user = new User({
        firstName : req.body.firstName,
        lastName : req.body.lastName,
        userName : req.body.userName,
        password : req.body.password,
        email : req.body.email
    });
    bcrypt.hash(user.password,10,function(err,hash){
        if (err) {
            return next(err);
        }
        user.password = hash;
        user.save().then(data => {
            console.log('Successfully created a new user');
            res.redirect('/');
        }).catch(error => {
            console.log('error: '+error);
            res.status("123").send({errorMessage: error});
        })
    })
});
app.get('/',function(req,res) {
    res.sendFile(path.join(__dirname+'/views/login.html'));
});
app.get('/createuser',function(req,res) {
    res.sendFile(path.join(__dirname+'/views/signup.html'));
});
app.post('/login',function(req,res,next) {
    if (logging) console.log("LOGIN");
    passport.authenticate('local',function(error,user,info) { 
        if (logging)  {
            console.log("ERROR:"+error);
            console.log("INFO:"+info);
            console.log("AUTHENTICATE USER:"+user);
        }
        if (error) { return next(error); }
        if (!user) { 
            if (logging) {
                if (typeof info != "undefined" && typeof info.message != "undefined") {
                    console.log("MESSAGE: "+info.message);
                } else {
                    console.log("MESSAGE: Unknown error with database.");
                }
            }
            return res.redirect('/login'); 
        }
        req.logIn(user,function(err) {
            if (logging) console.log("REDIRECT ERROR:"+err);
            req.session.user = user;
            res.redirect('/users');
        });
    })(req, res, next);
});
app.get('/logout',
  function(req, res){
    if (logging) console.log("LOGOUT");
    req.logout();
    req.session.destroy(function (err) {
        if (err) return next(err);
        res.redirect('/'); 
    });
});
app.get('/users',function(req,res) {
    if (logging) {
        console.log("AUTHENTICATE: "+req.isAuthenticated());
        if (typeof req.user != "undefined" && typeof req.user.userName != "undefined") console.log("USER: "+req.user.userName);
    }
    User.find({},(error,result) => {
        if (logging) console.log("RESULT: "+result);
        if (result) {
            res.render('availableUsers',{'userList':result});
        } else {
            res.status(403);
        }
    });
});
module.exports = app;