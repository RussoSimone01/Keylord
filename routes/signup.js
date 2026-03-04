import { Router } from 'express';
var router = Router();
import { hashSync } from 'bcrypt';
import { fixedEncodeURIComponent } from '../public/javascripts/sanitizer.js';
import getConnection from '../public/javascripts/connessione.js';
import crypto from '../public/javascripts/security.js';

var options = {
    imglock: '',
    error: false,
    email: false
};

router.route('/')
    .all(function (req, res, next) {
        req.session.regenerate(function (err) {
            if (err) throw err;
        });
        options.title = req.t("signup.title");
        next();
    })
    .get(function (req, res) {
        options.error = false;
        options.email = false;
        return res.render('signup', options);
    })
    .post(function (req, res) {
        if (req.body.Invia) {
            getConnection(function (err, connection) {
                if (err) {
                    console.error('error connecting: ' + err.stack);
                    return;
                }

                var nome = fixedEncodeURIComponent(req.body.nome);
                var pwd = fixedEncodeURIComponent(req.body.pwd);
                var salt = crypto.salt();
                var hash = hashSync(pwd, 10);
                var sql = 'INSERT INTO utenti VALUES (?, ?, ?, NULL, NULL, NULL)';
                connection.query(sql, [nome, hash, salt], function (error, results, fields) {
                    if (error) {	//username già in uso
                        console.log('An error has occurred', error);
                        options.error = true;
                        connection.release();
                        return res.render('signup', options);
                    }
                    else {
                        var email = fixedEncodeURIComponent(req.body.email);
                        sql = 'INSERT INTO sicurezza VALUES	(?, ?, default, NULL)';
                        connection.query(sql, [nome, email], function (error, results, fields) {
                            if (error) {	//email già in uso
                                connection.release();
                                options.email = true;
                                return res.render('signup', options);
                            }
                            else {
                                sql = 'SELECT PasswordSalt FROM utenti WHERE Utente = ?';
                                connection.query(sql, [nome], function (error, results, fields) {
                                    connection.release();
                                    if (error) throw error;
                                    req.session.user = nome;
                                    req.session.pass = crypto.derivaPassword(pwd, results[0].PasswordSalt);
                                    req.session.pin = null;
                                    return res.redirect('/options/securityManagement');
                                });
                            }
                        });
                    }
                });
            });
        }
        else
            return res.redirect('/signup');
    });

export default router;