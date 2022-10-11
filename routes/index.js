var express = require('express');
var router = express.Router();

/* Identifica il linguaggio */
router.all('/', function (req, res) {
  req.session.regenerate(function (err) {
    if (err) throw err;
  });
  var lang = req.acceptsLanguages('it', 'en');
  if (lang)
    return res.redirect('/it/login');
  else
    return res.redirect('/en/login');
});

module.exports = router;