var express = require('express');
var router = express.Router();

var options = {
    lang: 'it',
    title: 'Generatore',
    imglock: 'open-',
    user: ''
};

router.all('/', function (req, res) {
    if (req.session.user) {
        options.user = req.session.user;
        return res.render('it/random', options);
    }
    else
        return res.redirect('/it/login');
});

module.exports = router;