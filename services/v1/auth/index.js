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

const signIn = async (req, res)  => {
    try {
        let payload = await validate(req.body, SIGNIN)
        logging.debug(`[CHECK][PAYLOAD] >>>>> ${JSON.stringify(payload)}`)
        if (payload.length > 0) {
            results.error = 'ValidationError'
            results.errors = payload
            return res.status(BAD_REQUEST).send(results);
        }

        let isUser = await db.findOne(USER_COLLECTION, {username: payload.username, status: true})
        logging.debug(`[GET][USERNAME] >>>>> ${JSON.stringify(isUser)}`)
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
                userID: isUser._id.toString(),

            }
        )
        let refreshToken = crypt.genRefreshToken( {userID: isUser._id.toString() } )
        let now = new Date()
        let clause = { userID: isUser._id }
        let data = {
            $set: {
                userID: isUser._id,
                username: isUser.username,
                fullname: isUser.fullname || null,
                accessToken: token,
                refreshToken: refreshToken,
                roles: [],
                created: now,
                modified: now
            }
        }
        let options = { upsert: true, returnDocument: 'after'}

        const storeCredential = await db.findAndUpdate(USER_CREDENTIAL_COLLECTION, clause, data, options)
        logging.debug(`[SIGNIN][POST] >>>>> ${JSON.stringify(storeCredential)}`)
        if (undefined === storeCredential) {
            results.error = 'IncorectRequest'
            return res.status(BAD_REQUEST).send(result);
        }

        res.status(SUCCESS).send(data["$set"])
    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.error = 'ServerError'
        res.status(SERVER_ERROR).send(results)
    }
}

const sigRefreshToken = async (req, res)  => {
    try {
        let refreshToken = req.body.refreshToken || null
        if (null === refreshToken) {
            results.error = 'InvalidToken'
            return res.status(BAD_REQUEST).send(results);
        }

        let isTokenExist = await db.findOne(USER_CREDENTIAL_COLLECTION, {refreshToken: refreshToken})
        logging.debug(`[GET][REFRESH][TOKEN] >>>>> ${JSON.stringify(isTokenExist)}`)
        if (null === isTokenExist) {
            results.error = 'InvalidToken'
            return res.status(BAD_REQUEST).send(results);
        }

        let isTokenRefreshValid = crypt.verifyRefreshToken(isTokenExist.refreshToken)
        logging.debug(`[VERIFY][REFRESH][TOKEN] >>>>> ${JSON.stringify(isTokenRefreshValid)}`)
        if (!isTokenRefreshValid) {
            results.error = 'TokenExpired'
            return res.status(BAD_REQUEST).send(results);
        }

        let isTokenValid = crypt.verifyToken(isTokenExist.accessToken)
        logging.debug(`[VERIFY][TOKEN] >>>>> ${JSON.stringify(isTokenValid)}`)
        if (!isTokenValid) {
            results.error = 'TokenExpired'
            return res.status(BAD_REQUEST).send(results);
        }

        let refresh_token = crypt.genRefreshToken( {userID: isTokenExist.userID.toString() } )
        logging.debug(`[GEN][REFRESH][TOKEN] >>>>> ${JSON.stringify(refresh_token)}`)

        let clause = { userID: isTokenExist.userID }
        let data = {
            $set: {
                refreshToken: refresh_token,
                modified: new Date()
            }
        }
        let options = { upsert: false, returnDocument: 'after'}

        let updateCredential = await db.findAndUpdate(USER_CREDENTIAL_COLLECTION, clause, data, options)
        logging.debug(`[SIGNIN][PUT] >>>>> ${JSON.stringify(updateCredential)}`)
        let response = {
            accessToken: updateCredential.accessToken,
            refreshToken: updateCredential.refreshToken,
        }
        res.status(BAD_REQUEST).send(response);

    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.error = 'ServerError'
        res.status(SERVER_ERROR).send(results)
    }
}


module.exports = { signIn , sigRefreshToken}
