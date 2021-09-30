const fs = require('fs');
const logging = require(__dirname + '../../../../libs/logging');
const { verifyAccessToken } = require(__dirname + '../../../../libs/auth/jwtLibs');
const db = require(__dirname + '../../../../libs/db/mongoPromise');

const TOKEN_SECRET                  = process.env.APP_TOKEN_SECRET
const USER_CREDENTIAL_COLLECTION    = 'user_credential'

const UNAUTHORIZED                  = 401
const ACCESS_FORBIDDEN              = 403

const verifyToken = async (req, res, next) => {
    let results = { error: 'Invalid Token' }
    try {
        if (!req.headers['authorization']) return res.status(UNAUTHORIZED).json(results)

        let authHeader = req.headers['authorization']
        let bearerToken = authHeader.split(' ')
        let token = bearerToken[1]

        let isTokenValid = await verifyAccessToken(token, TOKEN_SECRET)
        logging.info(`[VERIFY][TOKEN][MIDDLEWARE] >>>>> ${JSON.stringify(isTokenValid)}`)
        if (!isTokenValid || isTokenValid.message == 'jwt expired') {
            results.error = 'Token Expired'
            return res.status(UNAUTHORIZED).json(results)
        }

        let isLogout = await db.findOne(USER_CREDENTIAL_COLLECTION, {userID: ObjectId(isTokenRefreshValid.aud), status: true})
        logging.debug(`[GET][CREDENTIAL] >>>>> ${JSON.stringify(isLogout)}`)
        if (null === isLogout) {
            results.error = 'Invalid Token'
            return res.status(UNAUTHORIZED).send(results);
        }

        req.payload = isTokenValid

        next()

    } catch (e) {
        logging.debug(`[VERIFY][TOKEN][MIDDLEWARE] >>>>> ${JSON.stringify(e.message)}`)
        results.error = 'Token Expired'
        return res.status(UNAUTHORIZED).json(results);
    }
}

module.exports = verifyToken;
