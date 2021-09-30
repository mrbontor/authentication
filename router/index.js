module.exports.routes =  (app, apiAuth) => {
    const ACTIVE_VERSION = process.env.ACTIVE_VERSION || v1;

    const signUp = require(__dirname + `../../services/${ACTIVE_VERSION}/signup`);
    const auth = require(__dirname + `../../services/${ACTIVE_VERSION}/auth`);

    const verifyToken = require(__dirname + `../../services/${ACTIVE_VERSION}/middleware`)


    app.route(`/api/${ACTIVE_VERSION}/signin`)
        .post(auth.signIn)

    app.route(`/api/${ACTIVE_VERSION}/refreshtoken`)
        .post(auth.refreshToken)

    app.route(`/api/${ACTIVE_VERSION}/signout`)
        .post(auth.signOut)

    app.route(`/api/${ACTIVE_VERSION}/signup`)
        .post(signUp)

    app.route(`/`)
        .post(verifyToken, (req, res, next) => {
            res.status(404).send({});
        })

    app.route(`/`)
        .get(verifyToken, (req, res, next) => {

            console.log(req.payload);
            res.send({message: `welcome buddy, you are home`});
        });
}
