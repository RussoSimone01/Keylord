var crypto = require('crypto');

//casting a Buffer
function objToBuff(obj) {
    return Buffer.isBuffer(obj) ? obj : Buffer.from(obj.data);
}

//cifratura utf-8 -> hex
function cifra(txt, password) {
    password = objToBuff(password);
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-cbc', password, iv);
    txt = cipher.update(txt, 'utf-8', 'hex');
    txt += cipher.final('hex');
    txt = iv.toString('hex') + ':' + txt; //iv:testoCifrato
    return txt;
}

//decifratura hex -> utf-8
function decifra(txt, password) {
    password = objToBuff(password);
    //recupero iv e testo cifrato
    var res = txt.split(':');
    var iv = Buffer.from(res.shift(), 'hex');
    var res = Buffer.from(res.join(':'), 'hex');
    var decipher = crypto.createDecipheriv('aes-256-cbc', password, iv);
    res = decipher.update(res, 'hex', 'utf-8');
    res += decipher.final('utf-8');
    return res;
}

function derivaPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
}

function salt() {
    return crypto.randomBytes(64);
}

module.exports = { cifra, decifra, derivaPassword, salt };