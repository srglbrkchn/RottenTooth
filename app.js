//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const https = require('https');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

// Global variables
let okMsg = false;
let userExists = true;
let alertTruthText = "";
let mailboxTxt = "";
let from = 2;
let alertMailText = "";
let alertMsgTxt = "";


app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.DB_HOST, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set('useCreateIndex', true);


const patientSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  badTooth: String,
  canOperate: Boolean,
  operatorMessage: {
    oId: String,
    oMessage: String
  },
  patientMessage: {
    pId: String,
    pMessage: String
  }
});


patientSchema.plugin(passportLocalMongoose);
patientSchema.plugin(findOrCreate);

const Patient = new mongoose.model("Patient", patientSchema);
passport.use(Patient.createStrategy());


// Created the cookie and stuffs it with a message, like user's identifications into the cookie
passport.serializeUser(function(patient, done) {
  done(null, patient);
});

// Passport during deserialization crumbles the cookid an discovers th user's info
passport.deserializeUser(function(patient, done) {
  done(null, patient);
});

// Google Authentication Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://shielded-dusk-19973.herokuapp.com/auth/google/rottentooth"
  },
  function(accessToken, refreshToken, profile, cb) {
    Patient.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

//Facebook Authentication Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://shielded-dusk-19973.herokuapp.com/auth/facebook/rottentooth"
  },
  function(accessToken, refreshToken, profile, cb) {
    Patient.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));




// Get Routes ----------
app.get('/', function(req, res) {
  res.render('home');
});

// Google Auth Route
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  }));

app.get('/auth/google/rottentooth',
  passport.authenticate('google', {
    failureRedirect: '/'
  }),
  function(req, res) {
    // Successful authentication, redirect personal page.
    res.redirect('/personalpage');
  });


// Facebook Auth Route
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/rottentooth',
  passport.authenticate('facebook', {
    failureRedirect: '/'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/personalpage');
  });


app.get('/truth', function(req, res) {
  if (req.isAuthenticated()) {
    alertMailText = "";
    Patient.find({
      'badTooth': {
        $ne: null
      }
    }, function(err, foundPatients) {
      if (err) {
        console.log(err);
      } else {
        res.render('truth', {
          foundPatients: foundPatients,
          alertTruthText: alertTruthText
        });
        alertTruthText = "";
      }
    });
  } else {
    res.redirect('/truthguest');
  }
});

app.get('/truthguest', function(req, res) {

  if (req.isAuthenticated()) {
    res.redirect('/truth');
  } else {
    Patient.find({
      'badTooth': {
        $ne: null
      }
    }, function(err, foundPatients) {
      if (err) {
        console.log(err);
      } else {
        res.render('truthguest', {
          foundPatients: foundPatients,
          alertTruthText: alertTruthText
        });
        alertTruthText = "";
      }
    });
  }

});

app.get('/signup', function(req, res) {
  res.render('signup', {
    alertText: " "
  });
});

app.get('/dentist', function(req, res) {

  if (req.isAuthenticated()) {
    alertMailText = "";
    res.render('dentist', {
      alertText: " "
    });
  } else {
    res.redirect('/');
  }
});


app.get('/personalpage', function(req, res) {

  if (req.isAuthenticated()) {

    alertMailText = "";

    const url = "https://zenquotes.io/api/random";
    let message = "";
    let writer = "";

    let totalMsg = 0;
    let approvedmsg = "";

    Patient.findById(req.user._id, function(err, foundPatient) {
      if (err) {
        console.log(err);
      } else {

        https.get(url, function(response) {
          response.on('data', function(data) {
            let quote = JSON.parse(data);

            message = quote[0].q;
            writer = quote[0].a;

            if (foundPatient.operatorMessage.oMessage != null) {
              totalMsg++;
            }

            if (foundPatient.patientMessage.pMessage != null) {
              totalMsg++;
            }

            if (okMsg == true) {
              approvedmsg = "Message sent successfully.....";
              okMsg = false;
            }

            if (okMsg == false && userExists == false) {
              approvedmsg = "User no longer exixts.";
              userExists = true;
            }

            res.render('personalpage', {
              message: message,
              writer: writer,
              approvedmsg: approvedmsg,
              totalMsg: totalMsg
            });

          });

        });
      }
    });
  } else {
    res.redirect('/');
  }

});


app.get('/message', function(req, res) {

  let patientId = " ";
  let operatorId = " ";
  res.render('message', {
    patientId: patientId,
    operatorId: operatorId,
    alertMsgTxt: alertMsgTxt
  });
});

app.get('/login', function(req, res) {
  let alertLoginTxt = "";
  res.render('login', {
    alertLoginTxt: alertLoginTxt
  });
});


app.get('/mailbox', function(req, res) {
  if (req.isAuthenticated()) {
    let totalMsg = 0;
    let patientMsg = 0;
    let operatorMsg = 0;

    Patient.findById(req.user._id, function(err, foundPatient) {
      if (err) {
        console.log(err);
      } else {
        if (foundPatient.operatorMessage.oMessage !== null) {
          totalMsg++;
          operatorMsg++;
        }

        if (foundPatient.patientMessage.pMessage !== null) {
          totalMsg++;
          patientMsg++;
        }
      }
      res.render('mailbox', {
        totalMsg: totalMsg,
        patientMsg: patientMsg,
        operatorMsg: operatorMsg,
        mailboxTxt: mailboxTxt,
        alertMailText: alertMailText
      });
    });

  } else {
    res.redirect('/');
  }

});


app.get('/logout', function(req, res) {
  if (req.isAuthenticated()) {
    // Cleaning the messages sent to this particular patient
    Patient.findById(req.user._id, function(err, foundPatient) {
      if (err) {
        console.log(err);
      } else {

        if (foundPatient.operatorMessage.oId != null) {
          Patient.findById(foundPatient.operatorMessage.oId, function(err, foundOperator) {
            if (err) {
              console.log(err);
            } else {
              foundOperator.canOperate = true;
              foundOperator.save(function() {});
            }

          });
        }

        foundPatient.operatorMessage.oId = null;
        foundPatient.operatorMessage.oMessage = null;
        foundPatient.patientMessage.pId = null;
        foundPatient.patientMessage.pMessage = null;

        foundPatient.save(function() {
          // Using passport logout() function to end the session and log out the user.
          req.logout();
          res.redirect('/');
        });
      }
    });
  } else {
    res.redirect('/');
  }

});

// Post Routs ----------

app.post('/signup', function(req, res) {

  const enteredUsername = req.body.username;

  if (req.body.password.length < 8) {
    const alertText = "Password should have 8 or more characters.";
    res.render('signup', {
      alertText: alertText
    });
  } else if (enteredUsername.length < 3) {
    const alertText = "Username should have 3 or more characters.";
    res.render('signup', {
      alertText: alertText
    });
  } else {

    Patient.find({
      username: req.body.username
    }, function(err, foundPatients) {
      if (err) {
        console.log(err);
      } else {
        // If the user does not exist in our database
        if (foundPatients.length === 0) {
          // register is a method in passport
          Patient.register({
            username: req.body.username,
            operatorMessage: {
              oId: null,
              oMessage: null
            },
            patientMessage: {
              pId: null,
              pMessage: null
            }
          }, req.body.password, function(err, patient) {
            if (err) {
              console.log(err);
              res.redirect('/register');
            } else {
              passport.authenticate('local')(req, res, function() {
                res.redirect('/personalpage');
              });
            }
          });
        } else {
          const alertText = "The username already exists. Please try a new one.";
          res.render('signup', {
            alertText: alertText
          });
        }
      }
    });

  }

});


app.post('/login', function(req, res, next) {

  const patient = new Patient({
    username: req.body.username,
    password: req.body.password
  });

  passport.authenticate('local', function(err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      alertLoginTxt = "invalid username or password.";
      return res.render('login', {
        alertLoginTxt: alertLoginTxt
      });
    }
    req.logIn(user, function(err) {
      if (err) {
        return next(err);
      }
      return res.redirect('/personalpage');
    });
  })(req, res, next);

});


app.post('/dentist', function(req, res) {
  const identifiedRottenTooth = req.body.givenTruth;
  let alertText = " ";

  if (identifiedRottenTooth.length === 0) {
    alertText = "Messagebox should not be empty.";
    res.render('dentist', {
      alertText: alertText
    });
  } else {

    Patient.findById(req.user._id, function(err, foundPatient) {
      if (err) {
        console.log(err);
      } else {
        if (foundPatient) {
          if (foundPatient.operatorMessage.oMessage == null) {
            if (foundPatient.badTooth == null) {
              foundPatient.badTooth = identifiedRottenTooth;
              foundPatient.save(function() {
                res.redirect('/truth');
              });
            } else {
              alertText = "Wait for someone to pull out your rotten tooth. Then you can move on to the next one.";
              res.render('dentist', {
                alertText: alertText
              });
            }

          } else {
            alertText = "First read your previous operator message.";
            res.render('dentist', {
              alertText: alertText
            });
          }
        }
      }
    });
  }

});


app.post('/pull', function(req, res) {

  if (req.isAuthenticated()) {
    const patientId = req.body.button;
    const operatorId = req.user._id;
    alertTruthText = "";

    if (patientId === operatorId) {
      alertTruthText = "You can not operate on yourself. Have some patience.";
      res.redirect("/truth");
    } else {

      Patient.findById(patientId, function(err, foundPatient) {
        if (err) {
          console.log(err);
        } else {
          if (foundPatient) {

            Patient.findById(operatorId, function(err, foundOperator) {
              if (err) {
                console.log(err);
              } else {
                if (foundOperator) {
                  let canOperate = foundOperator.canOperate;
                  let patientMessage = foundOperator.patientMessage.pMessage;

                  if (canOperate !== false) {

                    if (patientMessage === null) {

                      foundPatient.badTooth = null;
                      foundPatient.operatorMessage.oId = operatorId;
                      foundOperator.canOperate = false;

                      foundOperator.save(function() {});

                      foundPatient.save(function() {
                        res.render('message', {
                          patientId: patientId,
                          operatorId: operatorId,
                          alertMsgTxt: ""
                        });
                      });
                    } else {
                      alertTruthText = "You have a message from your previous patient. Please check it first before moving on to another patient.";
                      res.redirect("/truth");
                    }
                  } else {
                    alertTruthText = "You should wait for the response of your previous patient.";
                    res.redirect("/truth");
                  }

                }
              }
            });

          } else {
            alertTruthText = "User no longer exists.";
            res.redirect("/truth");
          }
        }
      });

    }

  } else {
    res.redirect('/');
  }
});


app.post('/message', function(req, res) {
  if (req.isAuthenticated()) {
    const operatorId = req.body.operatorId;
    const patientId = req.body.patientId;
    const operatorMessage = req.body.message;

    if (operatorMessage.length === 0) {
      res.render('message', {
        patientId: patientId,
        operatorId: operatorId,
        alertMsgTxt: "Messagebox should not be empty."
      });
    } else {

      Patient.findById(req.user._id, function(err, foundPatient) {
        if (err) {
          console.log(err);
        } else {
          if (foundPatient) {
            foundPatient.canOperate = false;
            foundPatient.save(function() {});
          }
        }
      });

      Patient.findById(req.body.patientId, function(err, foundPatient) {
        if (err) {
          console.log(err);
        } else {
          if (foundPatient) {
            foundPatient.operatorMessage.oId = operatorId;
            foundPatient.operatorMessage.oMessage = operatorMessage;

            foundPatient.save(function() {
              okMsg = true;
              res.redirect('/personalpage');
            });
          } else {

            Patient.findById(req.user._id, function(err, foundOperator) {
              if (err) {
                console.log(err);
              } else {
                if (foundOperator) {
                  foundOperator.canOperate = true;
                  foundOperator.save(function() {
                    okMsg = false;
                    userExists = false;
                    res.redirect('/personalpage');
                  });
                }
              }
            });

          }
        }
      });
    }
  } else {
    res.redirect('/');
  }
});


app.post('/answer', function(req, res) {

  if (req.isAuthenticated()) {
    const userId = req.user._id;
    const pressedBtn = req.body.button;


    if (pressedBtn === 'operator') {
      Patient.findById(userId, function(err, foundUser) {
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            if (foundUser.operatorMessage.oMessage == null) {
              mailboxTxt = "";
              alertMailText = "";
              from = 2;
              res.redirect('/mailbox');
            } else {
              from = 0;
              alertMailText = "";
              mailboxTxt = foundUser.operatorMessage.oMessage;
              res.redirect('/mailbox');
            }
          }
        }
      });
    }

    if (pressedBtn === 'patient') {
      Patient.findById(userId, function(err, foundUser) {
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            if (foundUser.patientMessage.pMessage == null) {
              mailboxTxt = "";
              alertMailText = "";
              from = 2;
              res.redirect('/mailbox');
            } else {
              from = 1;
              alertMailText = "";
              mailboxTxt = foundUser.patientMessage.pMessage;
              res.redirect('/mailbox');
            }
          }
        }
      });
    }

    if (pressedBtn === 'clear') {
      Patient.findById(userId, function(err, foundUser) {
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {

            if (from === 2) {
              alertMailText = "";
              mailboxTxt = "";
              res.redirect('/mailbox');
            }

            if (from === 0) {
              foundUser.operatorMessage.oMessage = null;
              const operatorId = foundUser.operatorMessage.oId;

              Patient.findById(operatorId, function(err, foundOperator) {
                if (err) {
                  console.log(err);
                } else {
                  if (foundOperator) {
                    foundOperator.canOperate = true;
                    foundOperator.save(function() {});
                  }
                }
              });

              foundUser.save(function() {
                mailboxTxt = "";
                alertMailText = "";
                okMsg = false;
                res.redirect('/mailbox');
              });
            }

            if (from === 1) {
              foundUser.patientMessage.pMessage = null;
              foundUser.patientMessage.pId = null;
              foundUser.save(function() {
                mailboxTxt = "";
                alertMailText = "";
                from = 2;
                okMsg = false;
                res.redirect('/mailbox');
              });
            }

          }
        }
      });
    } else {
      if (pressedBtn === 'answer') {

        if (from === 1) {
          alertMailText = "The door to communication is closed.";
          res.redirect('/mailbox');
        }

        if (from === 2) {
          alertMailText = "There is no one to answer to.";
          res.redirect('/mailbox');
        }

        if (from === 0) {
          Patient.findById(userId, function(err, foundUser) {
            if (err) {
              console.log(err);
            } else {
              if (foundUser) {
                const operatorId = foundUser.operatorMessage.oId;
                Patient.findById(operatorId, function(err, foundOperator) {
                  if (err) {
                    console.log(err);
                  } else {
                    if (foundOperator) {
                      foundOperator.patientMessage.pId = userId;
                      foundOperator.patientMessage.pMessage = req.body.answertxt;
                      foundOperator.canOperate = true;

                      foundOperator.save(function() {
                        alertMailText = "Message sent successfully....."
                        res.redirect('/mailbox');
                      });
                    }
                  }
                });

              }
            }
          });
        }

      }
    }

  } else {
    res.redirect('/');
  }
});



app.listen(process.env.PORT || 3000, function() {
  console.log('The server is up and running.');
});
