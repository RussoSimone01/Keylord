import { createPool } from 'mysql';

var pool = createPool({
    user: process.env.DB_USER,
    password: process.env.DB_PWD,
    database: process.env.DB_NAME
});

var getConnection = function (callback) {
    pool.getConnection(callback);
};

export default getConnection;