module.exports.routes = function(app) {
    const ACTIVE_VERSION = process.env.ACTIVE_VERSION || v1;

    const signUp = require(__dirname + `../../services/${ACTIVE_VERSION}/signup`);
    const auth = require(__dirname + `../../services/${ACTIVE_VERSION}/auth`);

    app.route(`/api/${ACTIVE_VERSION}/signin`)
        .post(auth.signIn)

    app.route(`/api/${ACTIVE_VERSION}/refreshtoken`)
        .post(auth.sigRefreshToken)

    app.route(`/api/${ACTIVE_VERSION}/signup`)
        .post(signUp)

}
