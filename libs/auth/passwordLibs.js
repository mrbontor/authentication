const Crypto = require('crypto');

const ALGORITM = 'sha512'

const genNumberCode = (max, min) => {
    return Math.floor(
        Math.random() * (max - 1 + 1) + min
    )
}

const genHashPassword = (password) => {
    return new Promise( resolve => {
        let salt = Crypto.randomBytes(128).toString('base64');
        let iterations = genNumberCode(10000, 1000);

        let hash = Crypto.pbkdf2Sync(password, salt, iterations, 64, ALGORITM).toString(`hex`);

        resolve( {
            salt: salt,
            hash: hash,
            iterations: iterations
        });
    });
}

const verifyHashPassword = (hash, salt, iterations, password) => {
    return new Promise( resolve => {

        let hashed = Crypto.pbkdf2Sync(password, salt, iterations, 64, ALGORITM).toString(`hex`);

        resolve(hashed)
    });
}

module.exports = {
    genNumberCode,
    genHashPassword,
    verifyHashPassword
};
