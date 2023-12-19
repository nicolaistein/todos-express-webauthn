var express = require('express');
const axios = require('axios');
var passport = require('passport');
var WebAuthnStrategy = require('passport-fido2-webauthn').Strategy;
var SessionChallengeStore = require('passport-fido2-webauthn').SessionChallengeStore;
var base64url = require('base64url');
var uuid = require('uuid').v4;
var db = require('../db');
const Corbado = require('corbado');
const corbado = new Corbado('pro-4817998336279299095', 'corbado1_iXVHYmlpoKMpkpEcR8gw8gFnmWwcwu');


var store = new SessionChallengeStore();

console.log("auth.js initialized")
passport.use(new WebAuthnStrategy({ store: store }, function verify(id, userHandle, cb) {
  console.log("passport.use", id, userHandle)
  db.get('SELECT * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
    var publicKey = row.public_key;
    db.get('SELECT * FROM users WHERE rowid = ?', [ row.user_id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
      if (Buffer.compare(row.handle, userHandle) != 0) {
        return cb(null, false, { message: 'Invalid key. '});
      }
      return cb(null, row, publicKey);
    });
  });
}, function register(user, id, publicKey, cb) {
  console.log("passport.register", user, id, publicKey)
  db.run('INSERT INTO users (username, name, handle) VALUES (?, ?, ?)', [
    user.name,
    user.displayName,
    user.id
  ], function(err) {
    if (err) { return cb(err); }
    var newUser = {
      id: this.lastID,
      username: user.name,
      name: user.displayName
    };
    db.run('INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)', [
      newUser.id,
      id,
      publicKey
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, newUser);
    });
  });
}));

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


var router = express.Router();

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.post('/login/public-key', passport.authenticate('webauthn', {
  failureMessage: true,
  failWithError: true
}), function(req, res, next) {
  res.json({ ok: true, location: '/' });
}, function(err, req, res, next) {
  var cxx = Math.floor(err.status / 100);
  if (cxx != 4) { return next(err); }
  res.json({ ok: false, location: '/login' });
});

router.post('/login/public-key/challenge', function(req, res, next) {
  store.challenge(req, function(err, challenge) {
    if (err) { return next(err); }
    res.json({ challenge: base64url.encode(challenge) });
  });
});

router.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

router.get('/signup', function(req, res, next) {
  res.render('signup');
});

router.post('/signup/public-key/challenge', function(req, res, next) {
    const username = 'pro-4817998336279299095';
    const password = 'corbado1_iXVHYmlpoKMpkpEcR8gw8gFnmWwcwu';

    const body = {
      username: req.body.username,
      userFullName: req.body.name,
      clientInfo: {
        remoteAddress: req.ip,
        userAgent: req.get('user-agent'),
      },
      credentialStatus: 'active',
    };

    axios.post('https://backendapi.corbado.io/v1/webauthn/register/start', body, {
      auth: {
        username,
        password,
      },
    }).then((response) => {
      console.log('Response from the server:', response.data);
      console.log('publicKeyCredentialCreationOptions:', response.data.publicKeyCredentialCreationOptions)
      var parsed = JSON.parse(response.data.publicKeyCredentialCreationOptions)
      console.log('parsed:', parsed.publicKey)
      res.json(parsed.publicKey);
    }).catch((error) => {
      console.error('Error making POST request:', error.message);
      throw error;
    });





/*
  var handle = Buffer.alloc(16);
  handle = uuid({}, handle);
  var user = {
    id: handle,
    name: req.body.username,
    displayName: req.body.name
  };
  store.challenge(req, { user: user }, function(err, challenge) {
    if (err) { return next(err); }
    user.id = base64url.encode(user.id);
    res.json({ user: user, challenge: base64url.encode(challenge) });
  });
  */
});

module.exports = router;
