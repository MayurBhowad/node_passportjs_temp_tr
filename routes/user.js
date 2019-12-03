const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport')

const User = require('../models/User');

router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/register', (req, res) => {
    res.render('register');
});

//Register handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];
    //check required fields
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'please fill in all fields' });
    }
    //check password match
    if (password !== password2) {
        errors.push({ msg: 'password do not match' });
    }
    //check password length
    if (password.length < 6) {
        errors.push({ msg: 'Password atleast 6 charecter' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors, name, email, password, password2
        });
    } else {
        //validation passed
        User.findOne({ email: email })
            .then(user => {
                if (user) {
                    errors.push({ msg: 'Email is already registered!' });
                    res.render('register', {
                        errors, name, email, password, password2
                    });
                } else {
                    const newUser = new User({
                        name, email, password
                    });

                    //hash password
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err;

                            newUser.password = hash;

                            newUser.save().then(user => {
                                req.flash('success_msg', 'You are now Registered');
                                res.redirect('/user/login');
                            }).catch(err => console.log(err));
                        });
                    });
                }
            });
    }
});

//Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/user/login',
        failureFlash: true
    })(req, res, next);
});

//logout
router.get('/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', 'You are logout');
    res.redirect('/user/login');
});

module.exports = router;