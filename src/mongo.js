
import mongodb from "mongodb";

export { ObjectID } from "mongodb";

export function create(config, cb) {

    let {
        host,
        port,
        database,
        journal = true,
        w       = 1
    } = config;

    const localServer = new mongodb.Server(host, port);

    const mongo = new mongodb.Db(database, localServer, {
        journal,
        w
    });

    mongo.open(function(err, db) {
        if(err) {
            return cb(err);
        }
        db.ObjectID = mongodb.ObjectID;
        return cb(null, db);
    });

}
