var express = require('express');
var app = express();
var path = require('path');
var loggedInUser = "";
var logging = true;
const port = process.env.PORT || 3001;

app.listen(port,() => {
    if (logging) console.log("Sever started at port "+port);
})

// Setup MongoDB database
const mongoose = require('mongoose');
mongoose.connect('mongodb://Admin:Password@127.0.0.1:27017/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false',
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
        if (logging) console.log(loggedInUser);
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
            // error
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