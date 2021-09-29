const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const TOKEN_SECRET          = process.env.APP_TOKEN_SECRET
const TOKEN_EXPIRY          = process.env.APP_TOKEN_EXPIRED
const REFRESH_TOKEN_SECRET  = process.env.APP_REFRESH_TOKEN_SECRET
const REFRESH_TOKEN_EXPIRY  = process.env.APP_REFRESH_TOKEN_EXPIRED

const ALGORITM = 'sha512'


const genToken = (data) => {
    try {
        if (data) {
            return jwt.sign(data, TOKEN_SECRET, { expiresIn: TOKEN_EXPIRY });
        }
    } catch (e) {
        return false;
    }
};

const genRefreshToken = (data) => {
    try {
        if (data) {
            return jwt.sign(data, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
        }
    } catch (e) {
        return false;
    }
};

const verifyToken = (token) => {
    try {
        if (token) {
            return jwt.verify(token, TOKEN_SECRET);
        }
    } catch(e) {
        return false
    }
};

const verifyRefreshToken = (token) => {
    try {
        if (token) {
            return jwt.verify(token, REFRESH_TOKEN_SECRET);
        }
    } catch(e) {
        // console.log(e);
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
    genRefreshToken,
    verifyToken,
    verifyRefreshToken,
    genNumberCode,
    genHashPassword,
    verifyHashPassword
};
