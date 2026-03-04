import { Router } from 'express';
var router = Router();

router.post('/', function (req, res, next) {
    var alphabet = "";
    if (req.body.low == "true")
        alphabet += "abcdefghijklmnopqrstuwxyz";
    if (req.body.cap == "true")
        alphabet += "ABCDEFGHIJKLMNOPQRSTUWXYZ";
    if (req.body.space == "true")
        alphabet += " ";
    if (req.body.num == "true")
        alphabet += "0123456789";
    if (req.body.spec == "true") {
        alphabet += "!\"#%&\\'()*+,-./:;=?@[\]^_`{|}~";
        if (req.body.tag == "false")
            alphabet += "<>";
    }

    var pass = "";
    var alphaLength = alphabet.length - 1;
    for (var i = 0; i < req.body.len; i++) {
        var n = Math.floor(Math.random() * alphaLength);
        pass += alphabet[n];
    }
    res.end(pass);
});

router.get('/', function (req, res, next) {
    var alphabet = "";
    if (req.query.low == "true")
        alphabet += "abcdefghijklmnopqrstuwxyz";
    if (req.query.cap == "true")
        alphabet += "ABCDEFGHIJKLMNOPQRSTUWXYZ";
    if (req.query.space == "true")
        alphabet += " ";
    if (req.query.num == "true")
        alphabet += "0123456789";
    if (req.query.spec == "true") {
        alphabet += "!\"#%&\\'()*+,-./:;=?@[\]^_`{|}~";
        if (req.query.tag == "false")
            alphabet += "<>";
    }

    var pass = "";
    var alphaLength = alphabet.length - 1;
    for (var i = 0; i < req.query.len; i++) {
        var n = Math.floor(Math.random() * alphaLength);
        pass += alphabet[n];
    }
    res.end(pass);
});

export default router;