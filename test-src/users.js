/*jshint newcap: false*/

"use strict";

var assert = require("assert");

var Transports = require("hudson-taylor/lib/transports");
var Client     = require("hudson-taylor/lib/client");
var Service    = require("hudson-taylor/lib/service");

var mongo = require('../lib/mongo');
var Users = require('../lib/users');

var bcrypt    = require('bcrypt');
var speakeasy = require('speakeasy');

var getRemote = function(db, options) {
  var transport = new Transports.Local();
  var client = new Client({
    users: transport
  });
  var service = Users(transport, db, options);
  return {
    transport,
    client,
    service
  };
};

var config = {
  mongo: {
    host:     "127.0.0.1",
    port:     27017,
    database: "ht-tests"
  }
};

describe("Users", function() {

  var db;

  var users, forgotpw;

  var user1 = {
    id:       "user1@localhost.com",
    password: "user1"
  };

  before((done) => {

    mongo.create(config.mongo, function(err, _db) {
      assert.ifError(err);
      db       = _db;
      users    = db.collection('users');
      forgotpw = db.collection('forgotpw');
      done();
    });

  });

  after((done) => {
    // scrub dbs after tests
    var drop = function(db, cb) {
      db.drop(function(err) {
        if(err) {
          if(err.errmsg != "ns not found") {
            return cb(err);
          }
        }
        cb();
      });
    };
    drop(users, function() {
      drop(forgotpw, done);
    });
  });

  it("should create an instance of user service", function() {

    var conn = getRemote(db);

    assert.equal(conn.service instanceof Service, true);
  
  });

  describe("create", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should successfully create a user", function(done) {

      conn.client.call("users", "create", user1, function(err, response) {

        assert.ifError(err);

        // Should be user id
        assert.equal(response.id, user1.id);

        users.find().toArray(function(err, users) {

          assert.ifError(err);

          assert.equal(users.length, 1);

          assert.equal(users[0].id, response.id);
          assert.notEqual(users[0].password, user1.password);

          done();

        });

      });

    });

    it("should not allow duplicate id", function(done) {

      conn.client.call("users", "create", user1, function(err, response) {

        assert.ifError(err);

        assert.deepEqual(response, { error: 'user-exists', id: user1.id }, 'Duplicate user was created.');

        done();

      });

    });

    it("should allow saving optional data", function(done) {

      var user3 = {
        id: "optionalDataUID",
        password: "optionalDataPass",
        data: {
          hello: "world"
        }
      };

      conn.client.call("users", "create", user3, function(err, response) {

        assert.ifError(err);

        assert.deepEqual(response, { id: user3.id });

        users.findOne({
          id: user3.id
        }, function(err, user) {

          assert.ifError(err);

          assert.deepEqual(user.data, user3.data);

          done();

        });

      });

    });

    it("should require user password by default", function(done) {

      conn.client.call("users", "create", {
        id: "hello"
      }, function(err) {

        assert.equal(err.error, "Missing attribute 'schema.password': required String");

        done();

      });

    });

    it("should not require password when requirePassword is set to false", function(done) {

      var conn = getRemote(db, {
        requirePassword: false
      });

      var uId = "requirePasswordTestUID";

      conn.client.call("users", "create", {
        id: uId
      }, function(err, response) {

        assert.ifError(err);

        assert.deepEqual(response, { id: uId });

        done();

      });

    });

  });

  describe("get", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should successfully get user", function(done) {

      conn.client.call("users", "get", {
        id: user1.id
      }, function(err, user) {

        assert.ifError(err);

        assert.equal(user.id, user1.id);

        assert.equal(user.password, undefined);

        done();

      });

    });

    it("should fail to get nonexistant user", function(done) {

      conn.client.call("users", "get", {
        id: "NOPE"
      }, function(err, user) {

        assert.ifError(err);

        assert.deepEqual(user, { error: "not-found" });

        done();

      });

    });

  });

  describe("update", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should update users data", function(done) {

      var data = {
        hello: "world"
      };

      conn.client.call("users", "update", {
        id:   user1.id,
        data
      }, function(err) {

        assert.ifError(err);

        users.findOne({
          id: user1.id
        }, function(err, user) {

          assert.ifError(err);

          assert.notEqual(user, undefined);

          assert.deepEqual(user.data, data);

          done();

        });

      });

    });

  });

  describe("updatePassword", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should fail if wrong old password", function(done) {

      conn.client.call("users", "updatePassword", {
        id:      user1.id,
        oldPass: user1.password + "invalid",
        newPass: "doesntmatter"
      }, function(err, result) {

        assert.ifError(err);

        assert.deepEqual(result, { error: "invalid" });

        done();

      });

    });

    it("should update a users password", function(done) {

      var newPass = user1.password + "_new";

      conn.client.call("users", "updatePassword", {
        id:      user1.id,
        oldPass: user1.password,
        newPass
      }, function(err, result) {

        assert.ifError(err);

        assert.deepEqual(result, { result: "success" });

        users.findOne({
          id: user1.id
        }, function(err, user) {

          assert.ifError(err);

          assert.equal(bcrypt.compareSync(user1.password, user.password), false);
          assert.equal(bcrypt.compareSync(newPass, user.password), true);

          user1.password = newPass;

          done();

        });

      });

    });

    it("should allow setting same password (hash will change w/ bcrypt)", function(done) {

      users.findOne({
        id: user1.id
      }, function(err, user) {

        assert.ifError(err);

        var oldPasswordHash = user.password;

        conn.client.call("users", "updatePassword", {
          id:      user1.id,
          oldPass: user1.password,
          newPass: user1.password
        }, function(err, response) {

          assert.ifError(err);

          assert.equal(response.result, "success");

          users.findOne({
            id: user1.id
          }, function(err, user) {

            assert.ifError(err);

            assert.notEqual(oldPasswordHash, user.password);

            done();

          });

        });

      });

    });

  });

  describe("initiateForgotPassword", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should return a challenge string", function(done) {

      conn.client.call("users", "initiateForgotPassword", {
        id: user1.id
      }, function(err, response) {

        assert.ifError(err);

        assert.notEqual(response.challenge, undefined);

        done();

      });

    });

    it("should allow setting custom expiry timeout", function(done) {

      var twoHours = 7200000;  

      var defaultTimeout = Date.now() + twoHours;

      conn.client.call("users", "initiateForgotPassword", {
        id:            user1.id,
        expiryTimeout: 604800000 // one week
      }, function(err, response) {

        assert.ifError(err);

        forgotpw.findOne({
          challenge: response.challenge
        }, function(err, entry) {

          assert.ifError(err);

          assert(entry.expires > defaultTimeout);

          done();

        });

      });

    });

  });

  describe("completeForgotPassword", function() {

    var conn, challenge;

    before(() => {
      conn = getRemote(db);
    });

    it("should return successful if given a valid challenge", function(done) {

      conn.client.call("users", "initiateForgotPassword", {
        id: user1.id
      }, function(err, response) {

        assert.ifError(err);

        challenge = response.challenge; // hacky, fix

        var newPassword = user1.password + "-new";

        conn.client.call("users", "completeForgotPassword", {
          id:          user1.id,
          challenge:   response.challenge,
          newPassword: newPassword
        }, function(err, response) {

          assert.ifError(err);

          assert.equal(response.success, true);

          user1.password = newPassword;

          done();

        });

      });

    });

    it("should have changed user password", function(done) {

      users.findOne({
        id: user1.id
      }, function(err, user) {

        assert.ifError(err);
        assert.notEqual(user, undefined);

        assert.equal(bcrypt.compareSync(user1.password, user.password), true);

        done();

      });

    });

    it("should remove resets when they have been used", function(done) {

      forgotpw.findOne({
        challenge
      }, function(err, entry) {

        assert.ifError(err);

        assert.equal(entry, undefined);

        done();

      });

    });

    it("should return unsuccessful if valid challenge has expired", function(done) {

      conn.client.call("users", "initiateForgotPassword", {
        id:            user1.id,
        expiryTimeout: -10000 // wheeee
      }, function(err, response) {

        assert.ifError(err);

        conn.client.call("users", "completeForgotPassword", {
          id:          user1.id,
          challenge:   response.challenge,
          newPassword: "password"
        }, function(err, response) {

          assert.ifError(err);

          assert.equal(response.success, false);

          done();

        });

      });

    });

    it("should return unsuccessful for all other cases", function(done) {

      conn.client.call("users", "completeForgotPassword", {
        id:          user1.id,
        challenge:   "invalid",
        newPassword: "password"
      }, function(err, response) {

        assert.ifError(err);

        assert.equal(response.success, false);

        done();

      });

    });

  });

  describe("MFA", function() {

    describe("TOTP", function() {

      describe("enable", function() {

        var conn;

        before(() => {
          conn = getRemote(db);
        });

        it("should return secret", function(done) {

          conn.client.call("users", "enableMFA", {
            id:   user1.id,
            type: "totp"
          }, function(err, response) {

            assert.ifError(err);

            assert.notEqual(response.secret, undefined);

            done();

          });

        });

        it("should have set temporary token on user account", function(done) {

          users.findOne({
            id: user1.id
          }, function(err, user) {

            assert.ifError(err);

            assert.notEqual(user._mfa_totp, undefined);

            done();

          });

        });

      });

      describe("confirm", function() {

        var conn;

        before(() => {
          conn = getRemote(db);
        });

        it("should return successful for valid otp", function(done) {

          conn.client.call("users", "enableMFA", {
            id:   user1.id,
            type: "totp"
          }, function(err, response) {

            assert.ifError(err);

            var otp = speakeasy.totp({ key: response.secret })

            conn.client.call("users", "validateMFA", {
              id:    user1.id,
              type:  "totp",
              data: {
                otp: otp
              }
            }, function(err, response) {

              assert.ifError(err);

              assert.deepEqual(response, { success: true });

              done();

            });

          });

        });

        it("should confirm otp when pending if successful", function(done) {

          users.findOne({
            id: user1.id
          }, function(err, user) {

            assert.ifError(err);

            assert.equal(user._mfa_totp, undefined);
            assert.notEqual(user.mfa_totp, undefined);

            done();

          });

        });

      });

    });

    describe("Yubikey", function() {

      describe("enable", function() {

        var conn;

        var otp = "abcdefghijklmnopqrstuv";

        before(() => {
          conn = getRemote(db);
        });

        it("should not enable yubikey MFA when no credentials are given", function(done) {

          conn.client.call("users", "enableMFA", {
            id:   user1.id,
            type: "yubikey",
            data: {
              otp
            }
          }, function(err) {

            assert.deepEqual(err, { error: "Failed to parse schema.type: string does not match enum: totp" });

            done();

          });

        });

        it("should set yubikey id", function(done) {

          conn = getRemote(db, {
            yubikeyClientId:     "1",
            yubikeyClientSecret: "2"
          });

          conn.client.call("users", "enableMFA", {
            id:   user1.id,
            type: "yubikey",
            data: {
              otp
            }
          }, function(err, response) {

            assert.ifError(err);

            assert.equal(response.success, true);

            users.findOne({
              id: user1.id
            }, function(err, user) {

              assert.ifError(err);
              assert.notEqual(user, undefined);

              assert.equal(user._mfa_yubikey, otp.substr(0, 12));
    
              done();

            });

          });

        });

      });

      describe("confirm", function() {

        // Not sure how to test this :(

        xit("should return successful for valid otp");
        xit("should confirm otp when pending is successful");

      });

    });

  });

  describe("lock", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should lock user", function(done) {

      conn.client.call("users", "lock", {
        id: user1.id
      }, function(err) {

        assert.ifError(err);

        users.findOne({
          id: user1.id
        }, function(err, user) {

          assert.ifError(err);
          assert.notEqual(user, undefined);

          assert.equal(user.locked, true);

          done();

        });

      });

    });

  });

  describe("unlock", function() {

    var conn;

    before(() => {
      conn = getRemote(db);
    });

    it("should unlock user", function(done) {

      conn.client.call("users", "unlock", {
        id: user1.id
      }, function(err) {

        assert.ifError(err);

        users.findOne({
          id: user1.id
        }, function(err, user) {

          assert.ifError(err);
          assert.notEqual(user, undefined);

          assert.equal(user.locked, false);

          done();

        });

      });

    });

  });

  describe("login", function() {

    var conn;

    var user2 = {
      id:       "id@user2",
      password: "password@user2"
    };

    before(() => {
      conn = getRemote(db);
    });

    before(function(done) {
      conn.client.call("users", "create", user2, function(err, response) {
        assert.ifError(err);
        assert.equal(response.id, user2.id);
        done();
      });
    });

    it("should return not-found if id does not exist", function(done) {

      conn.client.call("users", "login", {
        id: "doesnotexist",
        password: "NOPE"
      }, function(err, response) {

        assert.ifError(err);

        assert.deepEqual(response, { error: "not-found" });

        done();

      });

    });

    it("should not login successfully when using the wrong password", function(done) {

      conn.client.call("users", "login", {
        id: user2.id,
        password: user2.password + "nope"
      }, function(err, result) {

        assert.ifError(err);

        assert.deepEqual(result, { success: false });

        done();

      });

    });

    it("should login successfully when using the correct password", function(done) {

      conn.client.call("users", "login", {
        id:       user2.id,
        password: user2.password
      }, function(err, result) {

        assert.ifError(err);

        assert.deepEqual(result, { success: true });

        done();

      });

    });

    it("should not login successfully when account is locked", function(done) {

      conn.client.call("users", "lock", {
        id: user2.id
      }, function(err, response) {

        assert.ifError(err);

        assert.deepEqual(response, { success: true });

        conn.client.call("users", "login", {
          id:       user2.id,
          password: user2.password
        }, function(err, result) {

          assert.ifError(err);

          assert.deepEqual(result, { success: false });

          conn.client.call("users", "unlock", {
            id: user2.id
          }, function(err, response) {

            assert.ifError(err);

            assert.deepEqual(response, { success: true });

            done();

          });

        });

      });

    });

    it("should not require MFA while pending confirmation", function(done) {

      conn.client.call("users", "enableMFA", {
        id: user2.id,
        type: "totp"
      }, function(err, response) {

        assert.ifError(err);

        assert.notEqual(response.secret, undefined);

        conn.client.call("users", "login", {
          id:       user2.id,
          password: user2.password
        }, function(err, response) {

          assert.ifError(err);

          assert.deepEqual(response, { success: true });

          done();

        });

      });

    });

    it("should not successfully login when MFA is required", function(done) {

      users.findOne({
        id: user2.id
      }, function(err, user) {

        assert.ifError(err);

        var otp = speakeasy.totp({ key: user._mfa_totp });

        conn.client.call("users", "validateMFA", {
          id: user2.id,
          type: "totp",
          data: {
            otp
          }
        }, function(err, response) {

          assert.ifError(err);

          assert.deepEqual(response, { success: true });

          conn.client.call("users", "login", {
            id:       user2.id,
            password: user2.password
          }, function(err, response) {

            assert.ifError(err);

            assert.deepEqual(response, { success: false });

            done();

          });

        });

      });

    });

    it("should successfully login when MFA is required", function(done) {

      users.findOne({
        id: user2.id
      }, function(err, user) {

        assert.ifError(err);

        var otp = speakeasy.totp({ key: user.mfa_totp });

        conn.client.call("users", "login", {
          id:       user2.id,
          password: user2.password,
          mfa: [
            {
              type: "totp",
              data: {
                otp
              }
            }
          ]
        }, function(err, response) {

          assert.ifError(err);

          assert.deepEqual(response, { success: true });

          done();

        });

      });

    });

  });

});
