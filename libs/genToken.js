const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const SECRET = process.env.TOKEN_USER_SECRET
const EXPIRED = process.env.TOKEN_USER_EXPIRED
const ALGORITM = 'sha512'


const genToken = (data) => {
    try {
        if (data) {
            return jwt.sign(data, SECRET, { expiresIn: parseInt(EXPIRED) });
        }
    } catch (e) {
        console.log(e.stack);
        return false;
    }
};

const generateRefreshToken = (data) => {
    // create a refresh token that expires in 7 days
    return new db.RefreshToken({
        data,
        token: crypto.randomBytes(40).toString('hex'),
        expires: new Date(Date.now() + 7*24*60*60*1000)
    });
}

const verifyToken = (token) => {
    try {
        if (token) {
            return jwt.verify(token, SECRET);
        }
    } catch(e) {
        return false
    }
};

const genNumberCode = (max, min) => {
    return Math.floor(
     Math.random() * (max - 1 + 1) + min
    )
}

const genHashPassword = (password) => {
    let salt = crypto.randomBytes(128).toString('base64');
    let iterations = genNumberCode(10000, 1000);

    let hash = crypto.pbkdf2Sync(password, salt, iterations, 64, ALGORITM).toString(`hex`);

    return {
        salt: salt,
        hash: hash,
        iterations: iterations
    };
}

const verifyHashPassword = (hash, salt, iterations, password) => {
    return hash == crypto.pbkdf2Sync(password, salt, iterations, 64, ALGORITM).toString(`hex`);
}

module.exports = {
    genToken,
    verifyToken,
    genNumberCode,
    genHashPassword,
    verifyHashPassword
};
