const mongo = require(__dirname + '/mongoDriver')
const mongodb = require('mongodb')

const insertOne = (collection, data) => {
    return new Promise( (resolve, reject) => {
        mongo.insertOne(collection, data, (err, result) => {
            if(err) reject (err)
            resolve(result)
        })
    })
}

const updateOne = (collection, clause, data) => {
    return new Promise( (resolve, reject) => {
        mongo.updateOne(collection, clause, data, (err, result) => {
            if(err) reject(err)
            resolve(result)
        })
    })
}

const find = (collection, data, options = {}) => {
    return new Promise( (resolve, reject) => {
        mongo.find(collection, data, options, (err, result) => {
            if(err) reject(err)
            resolve(result)
        })
    })
}

const findOne = (collection, data) => {
    return new Promise( (resolve, reject) => {
        mongo.findOne(collection, data, (err, result) => {
            if(err) reject(err)
            resolve(result)
        })
    })
}

const findAndUpdate = (collection, clause, data, options = {}) => {
    return new Promise( (resolve, reject) => {
        // options = { upsert: false, returnOriginal: false, returnNewDocument: true };
        mongo.findOneAndUpdate(collection, clause, data, options, (err, result) => {
            if(err) reject(err);
            resolve(result.value);
        });
    });
}

const findAndDelete = (collection, clause, options = {}) => {
    return new Promise( (resolve, reject) => {
        // options = { upsert: false, returnOriginal: false, returnNewDocument: true };
        mongo.findOneAndDelete(collection, clause, options, (err, result) => {
            if(err) reject(err);
            resolve(result);
        });
    });
}

const deleteOne = (collection, clause) => {
    return new Promise( (resolve, reject) => {
        mongo.deleteOne(collection, clause, (err, result) => {
            if(err) reject(err)
            resolve(result)
        })
    })
}

const dataTable = (collection, options = {}) => {
    return new Promise( (resolve, reject) => {
        mongo.dataTable(collection, options, (err, result) => {
            if(err) reject(err)
            resolve(result)
        })
    })
}

const newID = (id) => {
    if (id) return new mongodb.ObjectId(id)
    else return new mongodb.ObjectId()
}

module.exports = {
    insertOne,
    updateOne,
    find,
    findOne,
    findAndUpdate,
    findAndDelete,
    deleteOne,
    dataTable,

    newID
}
