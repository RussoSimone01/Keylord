var express = require('express');
var router = express.Router();

var options = {
    imglock: 'open-',
    user: ''
};

router.all('/', function (req, res) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    options.user = req.session.user;
    options.title = req.t("generator.title");
    return res.render('random', options);
});

module.exports = router;