var mysql = require('mysql');
var conf = require('./config');

var pool = mysql.createPool({
    user: conf.user,
    password: conf.password,
    database: conf.database
});

var getConnection = function (callback) {
    pool.getConnection(callback);
};

module.exports = getConnection;