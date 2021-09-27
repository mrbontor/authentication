module.exports.routes = function(app) {
    const ACTIVE_VERSION = process.env.ACTIVE_VERSION || v1;

    const signup = require(__dirname + `../../services/${ACTIVE_VERSION}/signup`);
    const auth = require(__dirname + `../../services/${ACTIVE_VERSION}/auth`);

    app.route(`/api/${ACTIVE_VERSION}/signin`)
        .post(auth.signin)

    app.route(`/api/${ACTIVE_VERSION}/signup`)
        .post(signup)

}
