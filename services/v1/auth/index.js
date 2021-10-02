const fs = require('fs');
const ObjectId = require('mongodb').ObjectId;
const logging = require(__dirname + '../../../../libs/logging');
const validate = require(__dirname + '../../../../libs/validateSchema');
const db = require(__dirname + '../../../../libs/db/mongoPromise');
const { verifyHashPassword } = require(__dirname + '../../../../libs/auth/passwordLibs');
const {
    signAccessToken,
    signRefreshToken,
    verifyRefreshToken
} = require(__dirname + '../../../../libs/auth/jwtLibs');

const SIGNIN = JSON.parse(fs.readFileSync(__dirname + '/schema/signin.json'))

const SUCCESS               = 200
const SUCCESS_NO_CONTENT    = 204
const BAD_REQUEST           = 400
const UNAUTHORIZED          = 401
const ACCESS_FORBIDDEN      = 403
const NOT_FOUND             = 404
const UNPROCESSABLE_ENTITY  = 422
const SERVER_ERROR          = 500

const USER_COLLECTION       = 'user'
const USER_CREDENTIAL_COLLECTION = 'user_credential'
const ROLE_COLLECTION       = 'role'

let results = { message: '' }

const signIn = async (req, res)  => {
    try {
        let payload = await validate(req.body, SIGNIN)
        logging.debug(`[CHECK][PAYLOAD] >>>>> ${JSON.stringify(payload)}`)
        if (payload.length > 0) {
            results.message = 'Validation Error'
            results.errors = payload
            return res.status(BAD_REQUEST).send(results);
        }

        let isUser = await db.findOne(USER_COLLECTION, {username: payload.username})
        logging.debug(`[GET][USERNAME] >>>>> ${JSON.stringify(isUser)}`)
        if (isUser === null) {
            results.message: 'Login was failed.'
            return res.status(NOT_FOUND).send(results);
        }
        if (!isUser.status) {
            results.message = 'User not activated yet, please contact administrator'
            return res.status(UNPROCESSABLE_ENTITY).send(results);
        }

        let isPasswordValid = await verifyHashPassword(
            isUser.infologin.hash,
            isUser.infologin.salt,
            isUser.infologin.iterations,
            payload.password
        )
        logging.debug(`[CHECK][PASSWORD] >>>>> ${JSON.stringify(isPasswordValid)}`)
        if (!isPasswordValid) {
            results.message = 'Incorect Password or Username'
            return res.status(UNAUTHORIZED).send(results);
        }

        let now = new Date()
        let dataPayload = {
            userID: isUser._id.toString(),
            username: isUser.username,
            fullname: isUser.fullname || null,
            roles: [],
            created: now,
            modified: now
        }
        let token = await generateToken(dataPayload, isUser._id)
        if (!token) {
            results.message = 'Invalid Token'
            return res.status(UNAUTHORIZED).send(results);
        }

        res.status(SUCCESS).send({
            message: 'Login Success.',
            data: token
        })
    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.message = 'Server Internal Error'
        res.status(SERVER_ERROR).send(results)
    }
}

const refreshToken = async (req, res)  => {
    try {
        let refreshToken = req.body.refreshToken || null
        if (null === refreshToken) {
            results.message = 'RefreshToken is required'
            return res.status(BAD_REQUEST).send(results);
        }

        let isTokenRefreshValid = await verifyRefreshToken(refreshToken)
        logging.debug(`[VERIFY][REFRESH][TOKEN] >>>>> ${JSON.stringify(isTokenRefreshValid)}`)
        if (!isTokenRefreshValid) {
            results.message = 'Token Expired'
            return res.status(UNAUTHORIZED).send(results);
        }

        let isTokenExist = await db.findOne(USER_CREDENTIAL_COLLECTION, {userID: ObjectId(isTokenRefreshValid.aud)})
        logging.debug(`[GET][CREDENTIAL] >>>>> ${JSON.stringify(isTokenExist)}`)
        if (null === isTokenExist) {
            results.message = 'Invalid Token'
            return res.status(UNAUTHORIZED).send(results);
        }

        let now = new Date()
        let dataPayload = {
            userID: isTokenRefreshValid.aud,
            username: isTokenRefreshValid.username,
            fullname: isTokenRefreshValid.fullname || null,
            roles: [],
            created: now,
            modified: now
        }

        let newToken = await generateToken(dataPayload, ObjectId(isTokenRefreshValid.aud))
        if (!newToken) {
            results.message = 'Invalid Token'
            return res.status(UNAUTHORIZED).send(results);
        }

        res.status(SUCCESS).send({
            message: 'Success.',
            data: newToken
        });
    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.message = 'Internal Server Error'
        res.status(SERVER_ERROR).send(results)
    }
}

const signOut = async (req, res)  => {
    try {
        let refreshToken = req.body.refreshToken || null
        if (null === refreshToken) {
            results.message = 'RefreshToken is required'
            return res.status(BAD_REQUEST).send(results);
        }

        let isTokenRefreshValid = await verifyRefreshToken(refreshToken)
        logging.debug(`[VERIFY][REFRESH][TOKEN] >>>>> ${JSON.stringify(isTokenRefreshValid)}`)
        if (!isTokenRefreshValid) {
            results.message = 'Token Expired'
            return res.status(UNAUTHORIZED).send(results);
        }

        let deleteToken = await db.deleteOne(USER_CREDENTIAL_COLLECTION, {userID: ObjectId(isTokenRefreshValid.aud)})
        logging.debug(`[DELETE][CREDENTIAL] >>>>> ${JSON.stringify(deleteToken)}`)
        if (null === deleteToken) {
            results.message = 'Invalid Token'
            return res.status(UNAUTHORIZED).send(results);
        }

        res.status(SUCCESS_NO_CONTENT).send({})
    } catch (e) {
        logging.error(`[SIGNIN][ERROR] >>>>> ${JSON.stringify(e.stack)}`)
        results.message = 'Server Internal Error'
        res.status(SERVER_ERROR).send(results)
    }
}

const generateToken = async (payload, userID) => {
    try {
        let accessToken = await signAccessToken(payload, userID.toString())
        let refreshToken = await signRefreshToken(payload, userID.toString())

        let clause = { userID: userID }
        let options = { upsert: true, returnDocument: 'after'}
        let data = {
            $set: {
                token: refreshToken,
                status: true,
                modified: payload.modified
            }
        }

        let update = await db.findAndUpdate(USER_CREDENTIAL_COLLECTION, clause, data, options)
        logging.debug(`[GENERATE][TOKEN] >>>>> ${JSON.stringify(update)}`)
        if (update) {
            return { accessToken, refreshToken };
        }
    } catch (e) {
        logging.error(`[GENERATE][TOKEN] >>>>> ${JSON.stringify(e.stack)}`)
        return false;
    }
}

module.exports = { signIn , refreshToken, signOut}
