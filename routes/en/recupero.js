var express = require('express');
var router = express.Router();
var crypto = require('../../public/javascripts/cifratura');
var bcrypt = require('bcrypt');
var sanitizer = require('../../public/javascripts/sanitizer');
var getConnection = require('../../public/javascripts/connessione');

var options = {
    lang: 'en',
    title: 'Recovery',
    imglock: '',
    invia: false,
    noUser: false,
    noPin: false,
    lock: false,
    error: false,
    tentaPin: 0,
    tentaPwd: 0,
    noSessionUserPin: true,
    same: false
};

router.post('/', function (req, res) {
    options.tentaPin = 3;
    if (req.body.Invia) {
        options.invia = {
            continua: false,
            conferma: false
        };

        getConnection(function (err, connection) {
            if (err) {
                console.error('error connecting: ' + err.stack);
                return;
            }

            if (req.body.Invia == 'CONTINUE') {
                options.invia.continua = true;
                options.noUser = true;
                options.noPin = true;
                options.lock = true;
                options.error = true;

                var User = sanitizer.fixedEncodeURIComponent(req.body.User);
                var Pin = sanitizer.fixedEncodeURIComponent(req.body.Pin);

                var sql = 'SELECT * FROM utenti JOIN sicurezza USING(Utente) WHERE Utente = ?';
                connection.query(sql, [User], function (error, results, fields) {
                    if (error) throw error;
                    if (results.length == 1) {
                        options.noUser = false;
                        var result = results[0];

                        if (result.PIN)
                            options.noPin = false;

                        options.tentaPin = result.TentativiPIN;
                        options.tentaPwd = result.TentativiPassword;
                        if (!options.noPin && options.tentaPin && bcrypt.compareSync(Pin, result.PIN)) {
                            req.session.user = User;
                            req.session.pin = crypto.derivaPassword(Pin, result.PINSalt);
                            req.session.pinChiaro = Pin;
                            options.tentaPin = 3;
                            options.tentaPwd = 3;
                            options.error = false;
                        }
                        else if (options.tentaPin > 0)
                            options.tentaPin--;

                        if (options.tentaPin > 0)
                            options.lock = false;

                        sql = 'UPDATE sicurezza SET TentativiPassword = ?, TentativiPIN = ? WHERE Utente = ?';
                        connection.query(sql, [options.tentaPwd, options.tentaPin, User], function (error, results, fields) {
                            if (error) throw error;
                        });
                    }
                    connection.release();
                    options.noSessionUserPin = !(req.session.user && req.session.pin);
                    return res.render('en/recupero', options);
                });
            }
            else if (req.body.Invia == 'CONFIRM') {
                options.invia.continua = false;
                options.invia.conferma = true;

                var newpwd = sanitizer.fixedEncodeURIComponent(req.body.newpwd);
                sql = 'SELECT Password FROM utenti WHERE Utente = ?';
                connection.query(sql, [req.session.user], function (error, results, fields) {
                    if (error) throw error;
                    options.same = bcrypt.compareSync(newpwd, results[0].Password);

                    if (options.same) {
                        connection.release();
                        return res.render('en/recupero', options);
                    }
                    var salt = crypto.salt();
                    var hash = bcrypt.hashSync(newpwd, 10);

                    sql = 'UPDATE utenti SET Password = ?, PasswordSalt = ? WHERE Utente = ?';
                    connection.query(sql, [hash, salt, req.session.user], function (error, results, fields) {
                        if (error) throw error;
                    });

                    sql = 'SELECT PasswordSalt FROM utenti WHERE Utente = ?';
                    connection.query(sql, [req.session.user], function (error, results, fields) {
                        if (error) throw error;
                        newpwd = crypto.derivaPassword(newpwd, results[0].PasswordSalt);
                        var backup = crypto.cifra(req.session.pinChiaro, newpwd);
                        req.session.pinChiaro = null;

                        sql = 'UPDATE utenti SET Backup = ? WHERE Utente = ?';
                        connection.query(sql, [backup, req.session.user], function (error, results, fields) {
                            if (error) throw error;
                        });
                    });

                    sql = 'SELECT * FROM dati WHERE Utente = ? AND Backup IS NOT NULL';
                    connection.query(sql, req.session.user, function (error, results, fields) {
                        if (error) throw error;

                        sql = 'DELETE FROM dati WHERE Utente = ?';
                        connection.query(sql, req.session.user, function (error, results, fields) {
                            if (error) throw error;
                        });

                        sql = 'INSERT INTO dati VALUES(?, NULL, ?, ?, ?, ?)';
                        var sql2 = 'INSERT INTO dati VALUES(default, ?, ?, ?, ?, ?)';
                        var pin = req.session.pin;
                        var user = req.session.user;
                        options.noSessionUserPin = !(req.session.user && req.session.pin);
                        for (var row of results) {
                            //decifra con il PIN
                            var sito = crypto.decifra(row.SitoApp, pin);
                            var username = crypto.decifra(row.Username, pin);
                            var pass = crypto.decifra(row.Password, pin);

                            //cifra con la nuova password
                            sito = crypto.cifra(sito, newpwd);
                            username = crypto.cifra(username, newpwd);
                            pass = crypto.cifra(pass, newpwd);

                            connection.query(sql, [row.ID, user, sito, username, pass], function (error, results, fields) {
                                if (error) throw error;
                            });

                            connection.query(sql2, [row.ID, user, row.SitoApp, row.Username, row.Password], function (error, results, fields) {
                                if (error) throw error;
                            });
                        }
                        req.session.regenerate(function (err) {
                            if (err) throw err;
                        });
                        connection.release();
                        return res.render('en/recupero', options);
                    });
                });
            }
        });
    }
    else {
        req.session.regenerate(function (err) {
            if (err) throw err;
        });
        return res.redirect('/en/recupero');
    }
});

router.get('/', function (req, res) {
    req.session.regenerate(function (err) {
        if (err) throw err;
    });
    options.invia = false;
    options.noSessionUserPin = true;
    return res.render('en/recupero', options);
});

module.exports = router;