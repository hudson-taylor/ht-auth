
import crypto from "crypto";

import ht from "hudson-taylor";
import s  from "ht-schema";

import speakeasy from "speakeasy";
import yub       from "yub";
import async     from "async";
import chapi     from "chapi";

/*
 
  Arguments:

    - transport: Instance of ht.Transport
    - db:        Connected database instance, only mongodb supported at current time.
    - options:   Object containing options, see below
    - log:       Optional logging function, defaults to console.log

  Options:

    - requirePassword:     Require user to set passwords, defaults to true.
    - algorithm:           Password hashing algorithm, supports bcrypt, scrypt and pbkdf2, defaults to bcrypt.
    - pwAlgorithmOptions:  Child Object
    -   iterations:        Number of iterations, defaults to 150k for pbkdf2, and 10 for bcrypt
    -   maxTime:           (scrypt only) Seconds it should take to complete 1 hash, defaults to 0.2
    - pwResetTimeout:      Time until the password reset will expire, defaults to 2 hours from now.
    - totpKeyLength:       Length of the TOTP secret key given to user, defaults to 20.
    - yubikeyClientId:     Client ID for Yubico API, only necessary if you want to enable Yubikey MFA.
    - yubikeyClientSecret: Client Secret for Yubico API, only necessary if you want to enable Yubikey MFA.

*/

const optionsSchema = s.Object({ opt: true }, {
  requirePassword:    s.Boolean({ opt: true }),
  pwAlgorithm:        s.String({ opt: true, enum: [ "bcrypt", "scrypt", "pbkdf2" ] }),
  pwAlgorithmOptions: s.Object({ opt: true }, {
    iterations: s.Number({ opt: true }),
    maxTime:    s.Number({ opt: true })
  }),
  totpKeyLength:       s.Number({ opt: true }),
  yubikeyClientId:     s.String({ opt: true }),
  yubikeyClientSecret: s.String({ opt: true })
});

export default function(transport, db, options = {}, log = console.log) {

  try {
    optionsSchema.validate(options);
  } catch(e) {
    throw new Error("Invalid options: " + e.toString());
  }

  const service  = new ht.Service(transport, options);
  const users    = db.collection("users");
  const forgotpw = db.collection("forgotpw");

  db.ensureIndex('users', { id: 1 }, { unique: true, dropDups: true, w: 1 }, function(err) {

    if(err) {
      throw new Error("There was an error creating index on users collection: " + err);
    }

  });

  // Setup defaults for options
  let {
    requirePassword    = true,
    pwAlgorithm        = 'bcrypt',
    pwAlgorithmOptions = {},
    pwResetTimeout     = 7200000,
    totpKeyLength      = 20
  } = options;

  // Set default options depending on what algorithm is chosen

  switch(pwAlgorithm) {
    case "bcrypt": {
      if(!pwAlgorithmOptions.iterations) pwAlgorithmOptions.iterations = 10;
      break;
    }
    case "scrypt": {
      if(!pwAlgorithmOptions.maxTime) pwAlgorithmOptions.maxTime = 0.2;
      break;
    }
    case "pbkdf2": {
      if(!pwAlgorithmOptions.iterations) pwAlgorithmOptions.iterations = 150000;
      break;
    }
  }

  let mfaTypes = [ "totp" ];

  // Initialise third-party libraries needed

  if(options.yubikeyClientId && options.yubikeyClientSecret) {
    mfaTypes.push("yubikey");
    yub.init(options.yubikeyClientId, options.yubikeyClientSecret);
  }

  service.on("create", s.Object({
    id:       s.String({ opt: false               }),
    password: s.String({ opt: !requirePassword    }),
    data:     s.Object({ opt: true, strict: false })
  }), function(request, callback) {

    if(!requirePassword) {
      return addUser(request);
    }

    chapi[pwAlgorithm](pwAlgorithmOptions).hash(request.password, function(err, hash) {

      if(err) {
        console.error("Error hashing password:", err);
        return callback(err);
      }

      request.password = hash;

      addUser(request);

    });

    function addUser(user) {

      users.insert(user, { safe: true, w: 1 }, function(err) {

        if (err) {
            if (err.code === 11000) {
              // Duplicate id exists
              return callback(null, { 
                error: 'user-exists',
                id:    user.id 
              });
            }
            return callback(err);
        }

        return callback(null, {
          id: user.id
        });

      });

    }

  });

  service.on("get", s.Object({
    id: s.String({ opt: false })
  }), function(request, callback) {
    findUser(request.id, function(err, user) {
      if(err) {
        return callback(err);
      }
      if(!user) return callback(null, {
        error: "not-found"
      });
      delete user._id;
      delete user.password;
      return callback(null, user);
    });
  });

  service.on("update", s.Object({
    id:   s.String({ opt: false               }),
    data: s.Object({ opt: true, strict: false })
  }), function(request, callback) {

    users.update({
      id: request.id
    }, {
      $set: {
        data: request.data
      }
    }, { safe: true, w: 1 }, callback);

  });

  // TODO: split out password management functions into new file

  service.on("updatePassword", s.Object({
    id:      s.String({ opt: false }),
    oldPass: s.String({ opt: false }),
    newPass: s.String({ opt: false })
  }), function(request, callback) {

    findUser(request.id, function(err, user) {

      if(err) {
        console.error("Error finding user:", err);
        return callback(err);
      }

      if(!user) {
        return callback(null, { error: "not-found" });
      }

      chapi[pwAlgorithm](pwAlgorithmOptions).compare(request.oldPass, user.password, function(err, match) {

        if(err) {
          console.error("Error comparing password:", err);
          return callback(err);
        }

        if(!match) {
          return callback(null, {
            error: "invalid"
          });
        }

        chapi[pwAlgorithm](pwAlgorithmOptions).hash(request.newPass, function(err, hash) {

          if(err) {
            console.error("Error hashing password:", err);
            return callback(err);
          }

          users.update({
            id: request.id
          }, {
            $set: {
              password: hash
            }
          }, { safe: true, w: 1 }, function(err) {

            if(err) {
              console.error("Error updating user:", err);
              return callback(err);
            }

            return callback(null, {
              result: "success"
            });

          });

        });

      });

    });

  });

  service.on("initiateForgotPassword", s.Object({
    id:            s.String({ opt: false }),
    expiryTimeout: s.Number({ opt: true })
  }), function(request, callback) {

    crypto.randomBytes(20, function(err, bytes) {

      if(err) {
        console.error("Error generating password reset challenge:", err);
        return callback(err);
      }

      // TODO: hash this again? time tradeoff, make optional
      const challenge = bytes.toString("hex");

      forgotpw.insert({
        id:        request.id,
        challenge,
        expires:   Date.now() + (request.expiryTimeout || pwResetTimeout)
      }, { safe: true, w: 1 }, function(err) {

        if(err) {
          console.error("Error inserting password reset:", err);
          return callback(err);
        }

        return callback(null, {
          challenge
        });

      });

    });

  });

  service.on("completeForgotPassword", s.Object({
    id:          s.String({ opt: false }),
    challenge:   s.String({ opt: false }),
    newPassword: s.String({ opt: false })
  }), function(request, callback) {

    forgotpw.findAndRemove({
      id:        request.id,
      challenge: request.challenge
    }, [['id', 1]], { safe: true, w: 1 }, function(err, result) {

      if(err) {
        console.error("Error finding password reset:", err);
        return callback(err);
      }

      if(!result) {
        return callback(null, {
          success: false
        });
      }

      if(Date.now() > result.expires) {
        // Expired
        return callback(null, {
          success: false
        });
      }

      chapi[pwAlgorithm](pwAlgorithmOptions).hash(request.newPassword, function(err, hash) {

        if(err) {
          console.error("Error hashing password:", err);
          return callback(err);
        }

        users.update({
          id: request.id
        }, {
          $set: {
            password: hash
          }
        }, { safe: true, w: 1 }, function(err) {

          if(err) {
            console.error("Error updating user:", err);
            return callback(err);
          }

          return callback(null, { 
            success: true 
          });

        });

      });

    });

  });

  // TODO: Split MFA into seperate files
  service.on("enableMFA", s.Object({
    id:   s.String({ opt: false }),
    type: s.String({ opt: false, enum: mfaTypes }),
    data: s.Object({ opt: true,  strict: false })
  }), function(request, callback) {

    findUser(request.id, function(err, user) {

      if(err) {
        console.error("Error finding user:", err);
        return callback(err);
      }

      if(!user) {
        return callback(null, {
          error: "not-found"
        });
      }

      enableMFA[request.type](user, request.data, callback);

    });

  });

  service.on("validateMFA", s.Object({
    id:   s.String({ opt: false                 }),
    type: s.String({ opt: false, enum: mfaTypes }),
    data: s.Object({ opt: true,  strict: false  })
  }), function(request, callback) {

    findUser(request.id, function(err, user) {

      if(err) {
        console.error("Error finding user:", err);
        return callback(err);
      }

      if(!user) {
        return callback(null, {
          error: "not-found"
        });
      }

      validateMFA[request.type](user, request.data, callback);

    });

  });

  const enableMFA = {

    totp(user, data, callback) {

      if(user.mfa_totp) {
        return callback(null, {
          error: "already-enabled"
        });
      }

      crypto.randomBytes(20, function(err, bytes) {

        if(err) {
          console.error("Error generating totp secret:", err);
          return callback(err);
        }

        const secret = speakeasy.generate_key({ length: totpKeyLength }).hex;

        users.update({
          id: user.id
        }, {
          $set: {
            _mfa_totp: secret
          }
        }, { safe: true, w: 1 }, function(err) {

          if(err) {
            console.error("Error updating user:", err);
            return callback(err);
          }

          return callback(null, {
            secret
          });

        });

      });

    },

    yubikey(user, data, callback) {

      // We don't really need to have enable & confirm for yubikey, seeing as the
      // otp returned is proof enough that they have physical access, but for the sake
      // of keeping the API consistent, require confirm call too.

      const yubiId = data.otp.substr(0, 12);

      users.update({
        id: user.id
      }, {
        $set: {
          _mfa_yubikey: yubiId
        }
      }, { safe: true, w: 1 }, function(err) {

         if(err) {
          console.error("Error updating user:", err);
          return callback(err);
        }

        return callback(null, {
          success: true
        });

      });

    }

  }

  const validateMFA = {

    totp(user, data, callback) {

      const secret = user.mfa_totp || user._mfa_totp;

      if(!secret) {
        return callback(null, {
          error: "not-enabled"
        });
      }

      const otp = speakeasy.totp({ key: secret });

      const success = otp == data.otp;

      if(!success) {
        return finish();
      }

      if(user._mfa_totp) {

        // Confirmed TOTP, move _mfa_totp -> mfa_totp

        users.update({
          id: user.id
        }, {
          $set: {
            mfa_totp: secret
          },
          $unset: {
            _mfa_totp: ""
          }
        }, { safe: true, w: 1 }, function(err) {

          if(err) {
            console.error("Error updating user:", err);
            return callback(err);
          }

          finish();

        });

      } else {
        finish();
      }

      function finish() {
        return callback(null, {
          success
        });
      }

    },

    yubikey(user, data, callback) {

      const yubiId = user.mfa_yubikey || user._mfa_yubikey;

      if(!yubiId) {
        return callback(null, {
          error: "not-found"
        });
      }

      if(yubiId !== data.otp.substr(0, 12)) {
        return callback(null, {
          success: false
        });
      }

      yub.verify(data.otp, function(err, data) {

        if(err) {
          console.error("Error verifying yubikey otp:", err);
          return callback(err);
        }

        const valid = data.status === "OK" && data.signatureVerified === true && data.nonceVerified === true;

        if(!valid) {
          return callback(null, {
            success: false
          });
        }

        if(user._mfa_yubikey) {

          // Confirmed OTP, move _mfa_yubikey -> mfa_yubikey

          users.update({
            id: user.id
          }, {
            $set: {
              mfa_yubikey: yubiId
            },
            $unset: {
              _mfa_yubikey: ""
            }
          }, { safe: true, w: 1 }, function(err) {

            if(err) {
              console.error("Error updating user:", err);
              return callback(err);
            }

            finish();

          });

        } else {
          finish();
        }

        function finish() {
          return callback(null, {
            success
          });
        }

      });

    }

  }

  service.on("lock", s.Object({
    id: s.String({ opt: false })
  }), function(request, callback) {

    users.update({
      id: request.id
    }, {
      $set: {
        locked: true
      }
    }, { safe: true, w: 1 }, function(err) {

      if(err) {
        console.error("Error updating user:", err);
        return callback(err);
      }

      return callback(null, {
        success: true
      });

    });

  });

  service.on("unlock", s.Object({
    id: s.String({ opt: false })
  }), function(request, callback) {

    users.update({
      id: request.id
    }, {
      $set: {
        locked: false
      }
    }, { safe: true, w: 1 }, function(err) {

      if(err) {
        console.error("Error updating user:", err);
        return callback(err);
      }

      return callback(null, {
        success: true
      });

    });

  });

  service.on("login", s.Object({
    id:       s.String({ opt: false }),
    password: s.String({ opt: !requirePassword }),
    mfa:      s.Array({ opt: true }, [
      s.Object({ opt: false }, {
        type: s.String({ opt: false, enum: mfaTypes }),
        data: s.Object({ opt: false, strict: false  })
      })
    ])
  }), function(request, callback) {

    findUser(request.id, function(err, user) {

      if(err) {
        console.error("Error finding user:", err);
        return callback(err);
      }

      // Even though we return not-found here, we
      // should make it clear to the caller that they
      // should not differenciate between not-found
      // and success: false to the end user

      if(!user) {
        return callback(null, {
          error: "not-found"
        });
      }

      async.series([
        checkDisabled,
        checkPassword,
        checkMFA
      ], function(err, results) {

        if(err) {
          console.error("Error trying to check login:", err);
          return callback(err);
        }

        return callback(null, {
          success: results.every(function(result) {
            return result === true;
          })
        });

      });

      function checkDisabled(done) {
        return done(null, !user.locked);
      }

      function checkPassword(done) {

        if(!requirePassword) {
          return done(null, true);
        }

        chapi[pwAlgorithm](pwAlgorithmOptions).compare(request.password, user.password, done);

      }

      function checkMFA(done) {

        const neededTypes = mfaTypes.map(function(type) {
          return user['mfa_' + type] && type;
        }).filter(Boolean);

        if(!neededTypes.length) {
          return done(null, true);
        }

        if(!request.mfa) {
          return done(null, false);
        }

        if(neededTypes.length != request.mfa.length) {
          return done(null, false);
        }

        if(!neededTypes.every(function(type) {
          for(let i = 0; i < request.mfa.length; i++) {
            if(request.mfa[0].type == type) {
              return true;
            }
          }
          return false;
        })) {
          return done(null, false);
        }

        async.map(request.mfa, function(mfa, done) {

          validateMFA[mfa.type](user, mfa.data, function(err, result) {

            if(err) {
              return done(err);
            }

            if(result.error) {
              return done(null, false);
            }

            return done(null, result.success);

          });

        }, function(err, results) {

          if(err) {
            console.error("Error validating OTPs:", err);
            return callback(err);
          }

          if(results.filter(Boolean).length != neededTypes.length) {
            return done(null, false);
          }

          return done(null, true);

        });

      }

    });

  });

  function findUser(id, callback) {
    users.findOne({
      id
    }, callback);
  }

  return service;

};
