var mysql = require('mysql');
require('dotenv').config()

var pool = mysql.createPool({
    user: process.env.DB_USER,
    password: process.env.DB_PWD,
    database: process.env.DB_NAME
});

var getConnection = function (callback) {
    pool.getConnection(callback);
};

module.exports = getConnection;