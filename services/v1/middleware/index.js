const db = require(__dirname + '../../../../libs/mongoPromise');
const crypt = require(__dirname + '../../../../libs/genToken');


const verifyToken = (req, res, next) => {
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
}
