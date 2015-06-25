/*jshint newcap: false*/

"use strict";

var assert = require("assert");

var Transports = require("hudson-taylor/lib/transports");
var Client     = require("hudson-taylor/lib/client");
var Service    = require("hudson-taylor/lib/service");

var mongo   = require('../lib/mongo');
var Session = require('../lib/session');

var getRemote = function(db, options) {
	var transport = new Transports.Local();
	var client = new Client({
		sessions: transport
	});
	var service = Session(transport, db, options);
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

describe("Sessions", function() {

	var db, sessions;

	before(function(done) {

		mongo.create(config.mongo, function(err, _db) {
			assert.ifError(err);
			db = _db;
			sessions = db.collection('sessions');
			done();
		});

	});

	after(function(done) {
		// scrub db after tests
		sessions.drop(done);
	});

	it("should create an instance of session service", function() {

		var conn = getRemote(db);

		assert.equal(conn.service instanceof Service, true);
	
	});

	describe("create", function() {

		var conn;

		before(function() {
			conn = getRemote(db);
		});

		it("should enter data successfully", function(done) {

			var _data = { "hello": "world" };

			conn.client.call("sessions", "create", {
				data: _data
			}, function(err, response) {

				assert.ifError(err);

				// Should be a session ID
				assert(response.id);

				// session ID should not be an ObjectID
				assert.throws(function() {
					db.ObjectID(response.id);
				});

				sessions.find().toArray(function(err, sessions) {

					assert.ifError(err);

					assert.equal(sessions.length, 1);

					assert.equal(sessions[0]._id, response.id);

					assert(sessions[0].expires > Date.now());
					assert.deepEqual(sessions[0].data, _data);

					done();

				});

			});

		});

		it("should allow no extra data", function(done) {

			conn.client.call("sessions", "create", {}, function(err, response) {

				assert.ifError(err);

				// Should be a session ID
				assert(response.id);

				// Should be nothing stored in db
				sessions.findOne({
					_id: response.id
				}, function(err, session) {

					assert.ifError(err);

					assert(session);

					assert.deepEqual(session.data, {});

					done();

				});

			});

		});

		it("should allow set expiry time", function(done) {

			var expires = new Date();
			expires.setFullYear(expires.getFullYear() + 1);
			expires = expires.getTime();

			conn.client.call("sessions", "create", {
				data:    { test: 1234 },
				expires
			}, function(err, response) {

				assert.ifError(err);

				sessions.findOne({
					_id: response.id
				}, function(err, session) {

					assert.ifError(err);

					assert(session);

					assert.equal(session.expires, expires);

					done();

				});

			});

		});

	});

	describe("validate", function() {

		var conn;

		before(function() {
			conn = getRemote(db);
		});

    it("should not validate invalid session", function(done) {

			conn.client.call("sessions", "validate", {
				id: "12345678901234567890"
			}, function(err, response) {

				assert.ifError(err);

				assert.deepEqual(response, { error: "invalid" });

				done();

			});

		});

    it("should validate session successfully", function(done) {

      var data = {
        hello: 'world'
      };

      conn.client.call("sessions", "create", {
        data
      }, function(err, response) {

        assert.ifError(err);

        conn.client.call("sessions", "validate", {
          id: response.id
        }, function(err, response) {

          assert.ifError(err);

          assert.deepEqual(response, data);

          done();

        });

      });

    });

    it("should return error if session has expired", function(done) {

      conn.client.call("sessions", "create", {
        expires: 1
      }, function(err, response) {

        conn.client.call("sessions", "validate", {
          id: response.id
        }, function(err, response) {

          assert.ifError(err);

          assert.deepEqual(response, { error: "expired" });

          done();

        });

      });

    });

		it("should remove session from database if expired", function(done) {

      sessions.find({
        expires: {
          $lt: Date.now()
        }
      }).toArray(function(err, entries) {

        assert.ifError(err);

        assert.equal(entries.length, 0);

        done();

      });

    });

	});

});