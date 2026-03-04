import { Router } from 'express';
var router = Router();
import crypto from '../public/javascripts/security.js';
import { compareSync, hashSync } from 'bcrypt';
import { fixedEncodeURIComponent } from '../public/javascripts/sanitizer.js';
import getConnection from '../public/javascripts/connessione.js';

var options = {
    imglock: 'open-',
    user: '',
    azione: {},
    post: false,    //indica se l'utente sta ricevendo una risposta a una sua azione (a seguito di un post)
    pin: false,
    error: false,
    same: false,    //errore di eguaglianza tra dato da modificare e dato inserito
    email: '',
    csfrToken: ''
};

function reset() {
    options.azione = {};
    options.post = false;
    options.error = false;
    options.same = false;
    options.email = '';
    options.csfrToken = '';
}

router.route('/')
    .all(function (req, res) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        reset();
        options.azione = false;
        options.pin = req.session.pin != null;
        options.title = req.t("options.title");
        return res.render('options', options);
    });

router.route('/editPwd')    //cambio password
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.cambia = true;
        options.pin = req.session.pin != null;
        return res.render('options', options);
    })
    .post(function (req, res) {
        if (req.body.Cambia == 'CONFERMA' || req.body.Cambia == 'CONFIRM') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }

                options.azione.cambia = true;
                var newpwd = fixedEncodeURIComponent(req.body.newpwd);

                connection.query('SELECT Password FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;
                    //controllo sulla correttezza della vecchia password
                    options.error = !compareSync(fixedEncodeURIComponent(req.body.oldpwd), results[0].Password);
                    //verifica che nuova e vecchia password siano diverse
                    options.same = compareSync(newpwd, results[0].Password);
                    if (!options.error && !options.same) {
                        //aggiornamento password
                        var sql = 'UPDATE utenti SET Password = ?, PasswordSalt = ? WHERE Utente = ?';
                        var hash = hashSync(newpwd, 10);
                        var salt = crypto.salt();
                        connection.query(sql, [hash, salt, req.session.user], function (error, results, fields) {
                            if (error) throw error;
                        });
                        connection.query('SELECT PasswordSalt FROM utenti WHERE Utente=?', [req.session.user], function (error, results, fields) {
                            if (error) throw error;
                            newpwd = crypto.derivaPassword(newpwd, results[0].PasswordSalt);
                        });
                        //acquisizione di tutti i dati non di backup
                        connection.query('SELECT * FROM dati WHERE Utente=? AND Backup IS NULL', [req.session.user], function (error, results, fields) {
                            if (error) throw error;
                            var oldpwd = req.session.pass;
                            //criptazione dati con la nuova password
                            sql = 'UPDATE dati SET SitoApp = ?, Username = ?, Password = ? WHERE ID = ?';
                            for (var row of results) {
                                var sito = crypto.cifra(crypto.decifra(row.SitoApp, oldpwd), newpwd);
                                var user = crypto.cifra(crypto.decifra(row.Username, oldpwd), newpwd);
                                var pass = crypto.cifra(crypto.decifra(row.Password, oldpwd), newpwd);
                                connection.query(sql, [sito, user, pass, row.ID], function (error, results, fields) {
                                    if (error) throw error;
                                });
                            }
                            //in caso il pin sia impostato è necessario aggiornare il campo backup
                            if (req.session.pin) {
                                sql = 'UPDATE utenti SET Backup = ? WHERE Utente = ?';
                                connection.query('SELECT Backup FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                                    if (error) throw error;
                                    var backup = crypto.cifra(crypto.decifra(results[0].Backup, oldpwd), newpwd);
                                    connection.query(sql, [backup, req.session.user], function (error, results, fields) {
                                        if (error) throw error;
                                    });
                                });
                            }
                            options.post = true;
                            req.session.pass = newpwd;
                            connection.release();
                            return res.render('options', options);
                        });
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/editPwd');
    });

router.route('/deleteAccount')   //eliminazione account
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.elimina = true;
        options.pin = req.session.pin != null;
        return res.render('options', options);
    })
    .post(function (req, res) {
        if (req.body.Elimina == 'CONFERMA' || req.body.Elimina == 'CONFIRM') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }

                options.azione.elimina = true;
                options.error = true;
                connection.query('SELECT Password FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;
                    //controllo sulla correttezza della vecchia password
                    if (compareSync(fixedEncodeURIComponent(req.body.oldpwd), results[0].Password)) {
                        var sql = 'DELETE FROM utenti WHERE Utente = ?';
                        connection.query(sql, [req.session.user], function (error, results, fields) {
                            if (error) throw error;
                            connection.release();
                        });

                        req.session.regenerate(function (err) {
                            if (err) throw err;
                        });

                        return res.redirect('/login');
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/deleteAccount');
    });

router.route('/securityManagement')  //options della sicurezza (attivazione/disattivazione del PIN)
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.sicurezza = true;
        return res.render('options', options);
    })
    .post(function (req, res) {
        if (req.body.Salva == 'SALVA' || req.body.Salva == 'SAVE') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }
                options.azione.sicurezza = true;
                connection.query('SELECT Password FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;
                    //controllo sulla correttezza della vecchia password
                    options.error = !compareSync(fixedEncodeURIComponent(req.body.oldpwd), results[0].Password);
                    if (!options.error) {
                        if (req.body.sicurezza == 'nessuna') { //scelta di disattivazione del PIN
                            //eliminazione delle informazioni del vechio PIN
                            var sql = 'UPDATE utenti SET PIN = NULL, PINSalt = NULL, Backup = NULL WHERE Utente = ?';
                            connection.query(sql, [req.session.user], function (error, results, fields) {
                                if (error)
                                    throw error;
                            });

                            sql = 'UPDATE sicurezza SET TentativiPIN = NULL WHERE Utente = ?';
                            connection.query(sql, [req.session.user], function (error, results, fields) {
                                if (error) throw error;
                            });

                            sql = 'DELETE FROM dati WHERE Utente=? AND BACKUP IS NOT NULL';
                            connection.query(sql, [req.session.user], function (error, results, fields) {
                                if (error) throw error;
                            });

                            options.post = {
                                salva: true,
                                sicurezza: false
                            };
                            options.pin = false;
                            req.session.pin = null;

                            connection.release();
                            return res.render('options', options);
                        }
                        else if (req.body.sicurezza == 'pin') { //scelta di attivazione del PIN
                            if (req.session.pin) {
                                var sql = 'DELETE FROM dati WHERE Utente = ? AND BACKUP IS NOT NULL';
                                connection.query(sql, [req.session.user], function (error, results, fields) {
                                    if (error) throw error;;
                                });
                            }

                            var sql = 'UPDATE sicurezza SET TentativiPIN = 3 WHERE Utente = ?';
                            connection.query(sql, [req.session.user], function (error, results, fields) {
                                if (error) throw error;;
                            });

                            //inserimento del nuovo PIN
                            var pin = fixedEncodeURIComponent(req.body.pin);
                            var hash = hashSync(pin, 10);
                            var backup = crypto.cifra(pin, req.session.pass);
                            var salt = crypto.salt();
                            sql = 'UPDATE utenti SET PIN = ?, PINSalt = ?, Backup = ? WHERE Utente = ?';
                            connection.query(sql, [hash, salt, backup, req.session.user], function (error, results, fields) {
                                if (error) throw error;
                            });
                            sql = 'SELECT PINSalt FROM utenti WHERE Utente = ?';
                            connection.query(sql, [req.session.user], function (error, results, fields) {
                                if (error) throw error;
                                req.session.pin = crypto.derivaPassword(pin, results[0].PINSalt);

                                //creazione dati di backup
                                sql = 'INSERT INTO dati VALUES (default, ?, ?, ?, ?, ?)';
                                connection.query('SELECT * FROM dati WHERE Utente=? AND Backup IS NULL', [req.session.user], function (error, results, fields) {
                                    if (error) throw error;
                                    for (var row of results) {
                                        var sito = crypto.cifra(crypto.decifra(row.SitoApp, req.session.pass), req.session.pin);
                                        var user = crypto.cifra(crypto.decifra(row.Username, req.session.pass), req.session.pin);
                                        var pass = crypto.cifra(crypto.decifra(row.Password, req.session.pass), req.session.pin);

                                        connection.query(sql, [row.ID, req.session.user, sito, user, pass], function (error, results, fields) {
                                            if (error) throw error;
                                        });
                                    }
                                });
                                options.post = {
                                    salva: true,
                                    sicurezza: true
                                };
                                options.pin = true;

                                connection.release();
                                return res.render('options', options);
                            });
                        }
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/securityManagement');
    });

router.route('/editPin')   //modifica del PIN, solo se attivo
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.pin = true;
        options.pin = true;
        return res.render('options', options);
    })
    .post(function (req, res) {
        if (req.body.Pin == 'CONFERMA' || req.body.Pin == 'CONFIRM') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }
                options.azione.pin = true;
                options.pin = true;
                var newpin = fixedEncodeURIComponent(req.body.newpin);

                connection.query('SELECT PIN FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;

                    //controllo sulla correttezza del vecchio PIN
                    options.error = !compareSync(fixedEncodeURIComponent(req.body.oldpin), results[0].PIN);
                    //controllo che nuovo e vecchio PIN siano diversi
                    options.same = compareSync(newpin, results[0].PIN);

                    if (!options.error && !options.same) {
                        //aggiornamento informazioni relative al PIN
                        var hash = hashSync(newpin, 10);
                        var backup = crypto.cifra(newpin, req.session.pass);
                        var salt = crypto.salt();
                        var sql = 'UPDATE utenti SET PIN = ?, PINSalt = ?, Backup = ? WHERE Utente = ?';
                        connection.query(sql, [hash, salt, backup, req.session.user], function (error, results, fields) {
                            if (error) throw error;

                            connection.query('SELECT PINSalt FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                                if (error) throw error;
                                newpin = crypto.derivaPassword(newpin, results[0].PINSalt);

                                //aggiornamento dati di backup
                                sql = 'UPDATE dati SET SitoApp = ?, Username = ?, Password = ? WHERE ID = ?';
                                connection.query('SELECT * FROM dati WHERE Utente = ? AND Backup IS NOT NULL', [req.session.user], function (error, results, fields) {
                                    if (error) throw error;
                                    var oldpin = req.session.pin;
                                    for (var row of results) {
                                        var sito = crypto.cifra(crypto.decifra(row.SitoApp, oldpin), newpin);
                                        var user = crypto.cifra(crypto.decifra(row.Username, oldpin), newpin);
                                        var pass = crypto.cifra(crypto.decifra(row.Password, oldpin), newpin);

                                        connection.query(sql, [sito, user, pass, row.ID], function (error, results, fields) {
                                            if (error) throw error;
                                        });
                                    }
                                    req.session.pin = newpin;
                                    options.post = true;
                                    connection.release();
                                    return res.render('options', options);
                                });
                            });
                        });
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/editPin');
    });

router.route('/resetPin') //reset del PIN, solo se attivo
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.reset = true;
        options.pin = true;
        return res.render('options', options);
    })
    .post(function (req, res) {
        if (req.body.Reset == 'CONFERMA' || req.body.Reset == 'CONFIRM') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }
                options.azione.reset = true;
                var newpin = fixedEncodeURIComponent(req.body.newpin);

                connection.query('SELECT Password, PIN FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;

                    //controllo sulla correttezza della password
                    options.error = !compareSync(fixedEncodeURIComponent(req.body.pwd), results[0].Password);
                    //controllo che nuovo e vecchio PIN siano diversi
                    options.same = compareSync(newpin, results[0].PIN);
                    if (!options.error && !options.same) {
                        //aggiornamento pin
                        var hash = hashSync(newpin, 10);
                        var backup = crypto.cifra(newpin, req.session.pass);
                        var salt = crypto.salt();
                        var sql = 'UPDATE utenti SET PIN = ?, PINSalt = ?, Backup = ? WHERE Utente = ?';
                        connection.query(sql, [hash, salt, backup, req.session.user], function (error, results, fields) {
                            if (error) throw error;

                            connection.query('SELECT PINSalt FROM utenti WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                                if (error) throw error;
                                newpin = crypto.derivaPassword(newpin, results[0].PINSalt);
                                //acquisizione di tutti i dati di backup
                                connection.query('SELECT * FROM dati WHERE Utente = ? AND Backup IS NOT NULL', [req.session.user], function (error, results, fields) {
                                    if (error) throw error;
                                    var oldpin = req.session.pin;
                                    //criptazione dati con il nuovo PIN
                                    sql = 'UPDATE dati SET SitoApp = ?, Username = ?, Password = ? WHERE ID = ?';
                                    for (var row of results) {
                                        var sito = crypto.cifra(crypto.decifra(row.SitoApp, oldpin), newpin);
                                        var user = crypto.cifra(crypto.decifra(row.Username, oldpin), newpin);
                                        var pass = crypto.cifra(crypto.decifra(row.Password, oldpin), newpin);

                                        connection.query(sql, [sito, user, pass, row.ID], function (error, results, fields) {
                                            if (error) throw error;
                                        });
                                    }
                                    req.session.pin = newpin;
                                    options.post = true;
                                    connection.release();
                                    return res.render('options', options);
                                });
                            });
                        });
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/resetPin');
    });

router.route('/editEmail') //cambio dell'email
    .all(function (req, res, next) {
        if (!req.session.user)
            return res.redirect('/login');
        options.user = req.session.user;
        //options.csfrToken = req.csrfToken();
        next();
    })
    .get(function (req, res) {
        reset();
        options.azione.email = true;
        getConnection(function (err, connection) {
            if (err) {
                console.error('error connecting: ' + err.stack);
                return;
            }
            connection.query('SELECT Email FROM sicurezza WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                if (error) throw error;
                options.email = decodeURIComponent(results[0].Email);
                connection.release();
                return res.render('options', options);
            });
        });
    })
    .post(function (req, res) {
        if (req.body.Email == 'CONFERMA' || req.body.Email == 'CONFIRM') {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }
                options.azione.email = true;
                var newmail = fixedEncodeURIComponent(req.body.newmail);
                connection.query('SELECT Email, Password FROM sicurezza JOIN utenti USING(Utente) WHERE Utente = ?', [req.session.user], function (error, results, fields) {
                    if (error) throw error;
                    //controllo sulla correttezza della password
                    options.error = !compareSync(fixedEncodeURIComponent(req.body.pwd), results[0].Password);
                    //controllo che nuova e vecchia email siano diverse
                    options.same = newmail == results[0].Email;
                    if (!options.error && !options.same) {
                        //aggiornamento informazioni relative all'email
                        var sql = 'UPDATE sicurezza SET Email = ? WHERE Utente = ?';
                        connection.query(sql, [newmail, req.session.user], function (error, results, fields) {
                            if (error)
                                throw error;

                            options.post = true;
                            options.email = decodeURIComponent(newmail);
                            connection.release();
                            return res.render('options', options);
                        });
                    }
                    else {
                        connection.release();
                        return res.render('options', options);
                    }
                });
            });
        }
        else
            return res.redirect('/options/editEmail');
    });

export default router;