
"use strict";

var mongodb = require('mongodb');

exports.ObjectID = mongodb.ObjectID;
exports.mongodb  = mongodb;
exports.create   = create;

function create(config, cb) {

    var localServer = new mongodb.Server(config.host, config.port);

    var mongo = new mongodb.Db(config.database, localServer, {
        journal: config.journal !== undefined ? config.journal : true,
        w: config.w !== undefined ? config.w : 1
    });

    mongo.open(function(err, db) {
        if(err) {
            return cb(err);
        }
        db.ObjectID = mongodb.ObjectID;
        return cb(null, db);
    });

}
