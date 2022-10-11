var express = require('express');
var router = express.Router();
var crypto = require('../../public/javascripts/cifratura');
var bcrypt = require('bcrypt');
var sanitizer = require('../../public/javascripts/sanitizer');
var getConnection = require('../../public/javascripts/connessione');

var options = {
    lang: 'en',
    title: 'Login',
    imglock: '',
    error: false,
    lock: false,
    tentaPwd: 0,
    tentaPin: 0
};

router.route('/')
    .all(function (req, res, next) {
        req.session.regenerate(function (err) {
            if (err) throw err;
        });
        next();
    })
    .get(function (req, res) {
        options.error = false;
        options.lock = false;
        return res.render('en/login', options);
    })
    .post(function (req, res) {
        if (req.body.Invia) {
            options.error = true;

            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }

                var User = sanitizer.fixedEncodeURIComponent(req.body.User);
                var Pwd = sanitizer.fixedEncodeURIComponent(req.body.Pwd);

                var sql = 'SELECT * FROM utenti JOIN sicurezza USING(Utente) WHERE Utente=?';
                connection.query(sql, [User], function (error, results, fields) {
                    if (error) throw error;
                    if (results.length == 1) {
                        options.lock = true;
                        options.tentaPwd = results[0].TentativiPassword - 1;
                        options.tentaPin = results[0].TentativiPIN;

                        if (results[0].TentativiPassword > 0) {
                            options.lock = false;
                            if (bcrypt.compareSync(Pwd, results[0].Password)) {
                                options.error = false;
                                options.tentaPwd = 3;
                                options.tentaPin = results[0].PIN ? 3 : null;
                                req.session.user = User;
                                req.session.pass = crypto.derivaPassword(Pwd, results[0].PasswordSalt);
                                if (results[0].PIN && results[0].PINSalt)
                                    req.session.pin = crypto.derivaPassword(crypto.decifra(results[0].Backup, req.session.pass), results[0].PINSalt);
                                else
                                    req.session.pin = null;
                            }
                            else if (options.tentaPwd == 0)
                                options.lock = true;

                            sql = 'UPDATE sicurezza SET TentativiPassword = ?, TentativiPIN = ? WHERE Utente = ?';
                            var val = [options.tentaPwd, options.tentaPin, User];
                            connection.query(sql, val, function (error, results, fields) {
                                connection.release();
                                if (error) throw error;

                                if (options.error)
                                    return res.render('en/login', options);
                                else
                                    return res.redirect('/en/index');
                            });
                        }
                        else {
                            connection.release();
                            return res.render('en/login', options);
                        }
                    }
                    else {
                        connection.release();
                        return res.render('en/login', options);
                    }
                });
            });
        }
        else
            return res.redirect('/en/login');
    });

module.exports = router;