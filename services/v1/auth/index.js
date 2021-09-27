const fs = require('fs');
const logging = require(__dirname + '../../../../libs/logging');
const validate = require(__dirname + '../../../../libs/validateSchema');
const db = require(__dirname + '../../../../libs/mongoPromise');
const crypt = require(__dirname + '../../../../libs/genToken');

const SIGNIN = JSON.parse(fs.readFileSync(__dirname + '/schema/signin.json'))



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

const results = {}

const signin = async (req, res)  => {
    try {
        let payload = await validate(req.body, SIGNIN)
        logging.debug(`[CHECK][PAYLOAD] >>>>> ${JSON.stringify(payload)}`)
        if (payload.length > 0) {
            results.error = 'ValidationError'
            results.errors = payload
            return res.status(BAD_REQUEST).send(results);
        }

        let isUser = await db.findOne(USER_COLLECTION, {username: payload.username})
        logging.debug(`[CHECK][USERNAME] >>>>> ${JSON.stringify(isUser)}`)
        if (null === isUser) {
            results.error = 'NotFound'
            return res.status(NOT_FOUND).send(results);
        }

        let isPasswordValid = crypt.verifyHashPassword(
            isUser.infologin.hash,
            isUser.infologin.salt,
            isUser.infologin.iterations,
            payload.password
        )
        logging.debug(`[CHECK][PASSWORD] >>>>> ${JSON.stringify(isPasswordValid)}`)
        if (!isPasswordValid) {
            results.error = 'IncorectPasswordUsername'
            return res.status(BAD_REQUEST).send(results);
        }

        let token = crypt.genToken(
            {
                _id: isUser._id.toString(),

            }
        )

        res.status(CREATED).send(token)
    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.error = 'ServerError'
        res.status(SERVER_ERROR).send(results)
    }
}

module.exports = { signin }
