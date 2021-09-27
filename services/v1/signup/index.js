const fs = require('fs');
const logging = require(__dirname + '../../../../libs/logging');
const validate = require(__dirname + '../../../../libs/validateSchema');
const db = require(__dirname + '../../../../libs/mongoPromise');
const crypt = require(__dirname + '../../../../libs/genToken');

const SIGNUP = JSON.parse(fs.readFileSync(__dirname + '/schema/signup.json'))

const SUCCESS               = 200
const CREATED               = 201
const SUCCESS_NO_CONTENT    = 204
const BAD_REQUEST           = 400
const ACCESS_FORBIDDEN      = 403
const NOT_FOUND             = 404
const UNPROCESSABLE_ENTITY  = 422
const SERVER_ERROR          = 500

const USER_COLLECTION       = 'user'
const USER_CREDENTIAL_COLLECTION = 'user_credential'
const ROLE_COLLECTION       = 'role'

const signup = async (req, res)  => {
    let results = {}
    try {
        let payload = await validate(req.body, SIGNUP)
        logging.debug(`[CHECK][PAYLOAD] >>>>> ${JSON.stringify(payload)}`)
        if (payload.length > 0) {
            results.error = 'ValidationError'
            results.errors = payload
            return res.status(BAD_REQUEST).send(results);
        }

        let isDuplicateEmail = await db.findOne(USER_COLLECTION, {email: payload.email})
        logging.debug(`[CHECK][EMAIL] >>>>> ${JSON.stringify(isDuplicateEmail)}`)
        if (null !== isDuplicateEmail) {
            results.error = 'DuplicationEmail'
            return res.status(UNPROCESSABLE_ENTITY).send(results);
        }

        let isDuplicateUsername = await db.findOne(USER_COLLECTION, {username: payload.username})
        logging.debug(`[CHECK][USERNAME] >>>>> ${JSON.stringify(isDuplicateUsername)}`)
        if (null !== isDuplicateUsername) {
            results.error = 'DuplicationUsername'
            return res.status(UNPROCESSABLE_ENTITY).send(results);
        }

        let now = new Date()
        payload.status = false
        payload.created = now
        payload.modified = now

        let password = crypt.genHashPassword(payload.password)
        delete payload.password

        payload.infologin = password

        const store = await db.insertOne(USER_COLLECTION, payload)
        logging.debug(`[SIGNUP][POST] >>>>> ${JSON.stringify(store)}`)
        if (undefined === store) {
            results.error = 'IncorectRequest'
            return res.status(BAD_REQUEST).send(result);
        }

        res.status(CREATED).send({})
    } catch (e) {
        logging.error(`[SIGNUP][POST] >>>>> ${JSON.stringify(e.stack)}`)
        results.error = 'ServerError'
        res.status(SERVER_ERROR).send(results)
    }
}


module.exports = signup
