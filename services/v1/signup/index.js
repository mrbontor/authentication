const fs = require('fs');
const logging = require(__dirname + '../../../../libs/logging');
const validate = require(__dirname + '../../../../libs/validateSchema');
const db = require(__dirname + '../../../../libs/db/mongoPromise');
const { genHashPassword } = require(__dirname + '../../../../libs/auth/passwordLibs');
const {
    signAccessToken,
    signRefreshToken
} = require(__dirname + '../../../../libs/auth/jwtLibs');

const SIGNUP = JSON.parse(fs.readFileSync(__dirname + '/schema/signup.json'))

const SUCCESS               = 200
const CREATED               = 201
const BAD_REQUEST           = 400
const UNPROCESSABLE_ENTITY  = 422
const SERVER_ERROR          = 500

const USER_COLLECTION       = 'user'
const USER_CREDENTIAL_COLLECTION = 'user_credential'
const ROLE_COLLECTION       = 'role'

const signUp = async (req, res)  => {
    let results = {}
    try {
        let payload = await validate(req.body, SIGNUP)
        logging.debug(`[CHECK][PAYLOAD] >>>>> ${JSON.stringify(payload)}`)
        if (payload.length > 0) {
            results.error = 'Validation error'
            results.errors = payload
            return res.status(BAD_REQUEST).send(results);
        }

        let isDuplicateEmail = await db.findOne(USER_COLLECTION, {email: payload.email}, {projection: {email:1}} )
        logging.debug(`[CHECK][EMAIL] >>>>> ${JSON.stringify(isDuplicateEmail)}`)
        if (null !== isDuplicateEmail) {
            results.error = `${isDuplicateEmail.email} is already been registered`
            return res.status(UNPROCESSABLE_ENTITY).send(results);
        }

        let isDuplicateUsername = await db.findOne(USER_COLLECTION, {username: payload.username}, {projection: {username:1}} )
        logging.debug(`[CHECK][USERNAME] >>>>> ${JSON.stringify(isDuplicateUsername)}`)
        if (null !== isDuplicateUsername) {
            results.error = `${isDuplicateUsername.username} is already been used`
            return res.status(UNPROCESSABLE_ENTITY).send(results);
        }

        let now = new Date()
        payload.status = false
        payload.created = now
        payload.modified = now

        let password = await genHashPassword(payload.password)
        delete payload.password

        payload.infologin = password

        const store = await db.insertOne(USER_COLLECTION, payload)
        logging.debug(`[SIGNUP][POST] >>>>> ${JSON.stringify(store)}`)
        if (undefined === store.insertedId) {
            results.error = 'Incorect Request'
            return res.status(BAD_REQUEST).send(result);
        }

        await storeCredential(store.insertedId)

        res.status(CREATED).send({})
    } catch (e) {
        logging.error(`[SIGNUP][POST] >>>>> ${JSON.stringify(e.stack)}`)
        results.error = 'ServerError'
        res.status(SERVER_ERROR).send(results)
    }
}


const storeCredential = async (userID) => {
    try {
        let accessToken = await signAccessToken({userID: userID}, userID.toString())
        let refreshToken = await signRefreshToken({userID: userID}, userID.toString())
        let now = new Date()
        let data = {
            userID: userID,
            token: refreshToken,
            status: true,
            created: now,
            modified: now
        }
        const store = await db.insertOne(USER_CREDENTIAL_COLLECTION, data)
        logging.debug(`[CREDENTIAL][POST] >>>>> ${JSON.stringify(store)}`)
        if (store) {
            return { accessToken, refreshToken };
        }
    } catch (e) {
        logging.error(`[CREDENTIAL][POST] >>>>> ${JSON.stringify(e.stack)}`)
    }
}

module.exports = signUp
