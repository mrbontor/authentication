const Ajv = require("ajv")
const AjvFormats = require("ajv-formats")
const AjvErrors = require('ajv-errors')


async function isRequestValidated(request, type, allErrors = true, asyn = true) {
    const ajv = new Ajv.default({
        allErrors: allErrors,
        jsonPointers: true,
        async: asyn,
        loopRequired: Infinity
    });
    AjvFormats(ajv, {mode: "fast", keywords: true})
    AjvErrors(ajv)

    let valid = ajv.validate(type, request);

    let result = request
    if (!valid) {
        result = await parseErrors(ajv.errors);
    }

    return Promise.resolve(result);
}

async function parseErrors(validationErrors) {
    return validationErrors.map(el => {
        let param = el.params.additionalProperty
        let keyword = el.keyword
        if (el.keyword == "errorMessage") {
            el.params.errors.forEach(ele => {
                param = ele.params["missingProperty"] || ele.instancePath.slice(1)
                keyword = ele.keyword
            });
        }
        return {
            param: param,
            key: keyword,
            message: el.message
        };

    });
}

module.exports = isRequestValidated;
