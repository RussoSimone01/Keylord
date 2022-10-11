var express = require('express');
var router = express.Router();
var bcrypt = require('bcrypt');
var sanitizer = require('../../public/javascripts/sanitizer');
var getConnection = require('../../public/javascripts/connessione');
var crypto = require('../../public/javascripts/cifratura');

var options = {
	lang: 'it',
	title: 'Registrazione',
	imglock: '',
	error: false,
	email: false
};

router.get('/', function (req, res) {
	options.error = false;
	options.email = false;
	return res.render('it/registrazione', options);
});

router.post('/', function (req, res, next) {
	if (req.body.Invia) {
		getConnection(function (err, connection) {
			if (err) {
				console.error('error connecting: ' + err.stack);
				return;
			}

			var nome = sanitizer.fixedEncodeURIComponent(req.body.nome);
			var pwd = sanitizer.fixedEncodeURIComponent(req.body.pwd);
			var salt = crypto.salt();
			var hash = bcrypt.hashSync(pwd, 10);
			var sql = 'INSERT INTO utenti VALUES (?, ?, ?, NULL, NULL, NULL)';
			connection.query(sql, [nome, hash, salt], function (error, results, fields) {
				if (error) {	//username già in uso
					options.error = true;
					connection.release();
					return res.render('it/registrazione', options);
				}
				else {
					var email = sanitizer.fixedEncodeURIComponent(req.body.email);
					sql = 'INSERT INTO sicurezza VALUES	(?, ?, default, NULL)';
					connection.query(sql, [nome, email], function (error, results, fields) {
						if (error) {	//email già in uso
							connection.release();
							options.email = true;
							return res.render('it/registrazione', options);
						}
						else {
							sql = 'SELECT PasswordSalt FROM utenti WHERE Utente = ?';
							connection.query(sql, [nome], function (error, results, fields) {
								connection.release();
								if (error) throw error;
								req.session.user = nome;
								req.session.pass = crypto.derivaPassword(pwd, results[0].PasswordSalt);
								req.session.pin = null;
								return res.redirect('/it/gestione/sicurezza');
							});
						}
					});
				}
			});
		});
	}
	else
		return res.redirect('/it/registrazione');
});

module.exports = router;