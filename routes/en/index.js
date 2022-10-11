var express = require('express');
var getConnection = require('../../public/javascripts/connessione');
var router = express.Router();
var crypto = require('../../public/javascripts/cifratura');
var sanitizer = require('../../public/javascripts/sanitizer');

var options = {
    lang: 'en',
    title: 'Home',
    imglock: 'open-',
    user: '',
    msg: false,
    dati: [],
    csfrToken: ''
};

router.route('/')
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/en/login');
        options.user = req.session.user;
        next();
    })
    .post(function (req, res) {
        options.msg = {
            inserisci: false,
            modifica: false,
            elimina: false,
            errore: false
        };

        if (req.body.Invia) {
            var id = sanitizer.fixedEncodeURIComponent(req.body.id);

            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }

                if (req.body.Invia == 'DELETE') {
                    var sql = 'DELETE FROM dati WHERE ID = ?';
                    connection.query(sql, [id], function (error) {
                        if (error)
                            options.msg.errore = true;
                        else {
                            sql = 'DELETE FROM dati WHERE BACKUP = ?';
                            connection.query(sql, [id], function (error) {
                                if (error)
                                    options.msg.errore = true;
                                else
                                    options.msg.elimina = true;
                                connection.release();
                                setData(req.session, res);
                            });
                        }
                    });
                }
                else {
                    req.body.sito = sanitizer.fixedEncodeURIComponent(req.body.sito);
                    req.body.user = sanitizer.fixedEncodeURIComponent(req.body.user);
                    req.body.pwd = sanitizer.fixedEncodeURIComponent(req.body.pwd);

                    if (req.body.Invia == 'INSERT') {
                        var sql = 'INSERT INTO dati VALUES (default, NULL, ?, ?, ?, ?)';
                        var sito = crypto.cifra(req.body.sito, req.session.pass);
                        var user = crypto.cifra(req.body.user, req.session.pass);
                        var pwd = crypto.cifra(req.body.pwd, req.session.pass);

                        connection.query(sql, [req.session.user, sito, user, pwd], function (error) {
                            if (error)
                                options.msg.errore = true;
                            else if (req.session.pin) {
                                sito = crypto.cifra(req.body.sito, req.session.pin);
                                user = crypto.cifra(req.body.user, req.session.pin);
                                pwd = crypto.cifra(req.body.pwd, req.session.pin);

                                var sql = 'SELECT ID FROM dati ORDER BY ID DESC LIMIT 1';
                                connection.query(sql, function (error, results) {
                                    if (error)
                                        throw error;

                                    sql = 'INSERT INTO dati VALUES (default, ?, ?, ?, ?, ?)';
                                    connection.query(sql, [results[0].ID, req.session.user, sito, user, pwd], function (error) {
                                        if (error || options.msg.errore)
                                            options.msg.errore = true;
                                        else
                                            options.msg.inserisci = true;
                                    });
                                });
                            }
                            else
                                options.msg.inserisci = true;
                            connection.release();
                            setData(req, res);
                        });
                    }
                    else if (req.body.Invia == 'EDIT') {
                        var sql = 'UPDATE dati SET SitoApp = ?, Username = ?, Password = ? WHERE ID = ?';
                        var sito = crypto.cifra(req.body.sito, req.session.pass);
                        var user = crypto.cifra(req.body.user, req.session.pass);
                        var pwd = crypto.cifra(req.body.pwd, req.session.pass);

                        connection.query(sql, [sito, user, pwd, id], function (error) {
                            if (error)
                                options.msg.errore = true;
                            else if (req.session.pin) {
                                var sql = 'UPDATE dati SET SitoApp = ?, Username = ?, Password = ? WHERE BACKUP = ?';
                                sito = crypto.cifra(req.body.sito, req.session.pin);
                                user = crypto.cifra(req.body.user, req.session.pin);
                                pwd = crypto.cifra(req.body.pwd, req.session.pin);

                                connection.query(sql, [sito, user, pwd, id], function (error) {
                                    if (error || options.msg.errore)
                                        options.msg.errore = true;
                                    else
                                        options.msg.modifica = true;
                                });
                            }
                            else
                                options.msg.modifica = true;
                            connection.release();
                            setData(req, res);
                        });
                    }
                }
            });
        }
        else
            return res.redirect('/en/login');
    })
    .get(function (req, res) {
        options.msg = false;
        setData(req, res);
    });

function setData(req, res) {
    getConnection(function (err, connection) {
        if (err) {
            console.error('error connecting: ' + err.stack);
            return;
        }

        var sql = 'SELECT * FROM dati WHERE Utente=? AND Backup IS NULL;';
        connection.query(sql, [req.session.user], function (error, results, fields) {
            if (error) throw error;
            for (var i = 0; i < results.length; i++) {
                results[i].SitoApp = decodeURIComponent(crypto.decifra(results[i].SitoApp, req.session.pass));
                results[i].Username = decodeURIComponent(crypto.decifra(results[i].Username, req.session.pass));
                results[i].Password = decodeURIComponent(crypto.decifra(results[i].Password, req.session.pass));
            }
            options.dati = JSON.parse(JSON.stringify(results));
            connection.release();
            //options.csfrToken = req.csrfToken();
            return res.render('en/index', options);
        });
    });
}

module.exports = router;