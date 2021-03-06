
import crypto from "crypto";

import ht from "hudson-taylor";
import s  from "ht-schema";

/*
 
  Arguments:

    - transport: Instance of ht.Transport
    - db:        Connected database instance, only mongodb supported at current time.
    - options:   Object containing options, see below
    - log:       Optional logging function, defaults to console.log

  Options:

    - sessionIdLength: Length of sessionId given to client, defaults to 20 characters
    - sessionLength:   Time in milliseconds that a given session will time out, defaults to 3600000 (1 hour)

*/

export default function(transport, db, options = {}, log = console.log) {

	const service  = new ht.Service(transport, options);
	const sessions = db.collection("sessions");

	// Set defaults for options
	let {
		sessionIdLength = 20,
		sessionLength   = 3600000
	} = options;

	service.on("create", s.Object({
		expires: s.Number({ opt: true }),
		data:    s.Object({ opt: true, strict: false })
	}), function(request, callback) {

		// Ensure we can store specified data
		try {
			var data = JSON.parse(JSON.stringify(request.data || {}));
		} catch(e) {
			return callback(e);
		}

		const expiration = request.expires || (Date.now() + sessionLength);

		crypto.randomBytes(sessionIdLength / 2, function(err, bytes) {

			if(err) {
				return callback(err);
			}

			const sessionId = bytes.toString("hex");

			sessions.insert({
				_id:     sessionId,
				expires: expiration,
				data:    data
			}, { w: 1, safe: true }, function(err) {

				if(err) {
					return callback(err);
				}

				return callback(null, {
					id: sessionId
				});

			});

		});

	});

	service.on("validate", s.Object({
		id: s.String({ len: sessionIdLength })
	}), function(data, callback) {

		sessions.findOne({
			_id: data.id
		}, function(err, session) {

			if(err) {
				return callback(err);
			}

			if(!session) {
				return callback(null, {
					error: "invalid"
				});
			}

			if(Date.now() > session.expires) {
				// Session has expired
				return sessions.remove({
					_id: data.id
				}, { w: 1, safe: true }, function(err) {

					if(err) {
						return callback(err);
					}

					return callback(null, { error: "expired" });

				});

			}

			return callback(null, session.data);

		});

	});

	return service;

};
