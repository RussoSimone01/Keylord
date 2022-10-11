var express = require('express');
var router = express.Router();

var options = {
    lang: 'en',
    title: 'Generator',
    imglock: 'open-',
    user: ''
};

router.all('/', function (req, res) {
    if (req.session.user) {
        options.user = req.session.user;
        return res.render('en/random', options);
    }
    else
        return res.redirect('/en/login');
});

module.exports = router;