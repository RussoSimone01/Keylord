import { Router } from 'express';
var router = Router();

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

export default router;