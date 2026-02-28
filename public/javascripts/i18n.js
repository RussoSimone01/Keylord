const i18next = require('i18next');
const Backend = require('i18next-fs-backend');
const middleware = require('i18next-http-middleware');

i18next
    .use(Backend)
    .use(middleware.LanguageDetector)
    .init({
        fallbackLng: 'it',
        preload: ['it', 'en'],
        backend: {
            loadPath: __dirname + '/../../locales/{{lng}}/translation.json'
        },
        detection: {
            order: ['cookie', 'header'],
            caches: ['cookie'],
            lookupCookie: 'i18next',
            ignoreCase: true
        }
    }, (err, t) => {
        if (err) return console.log('something went wrong loading', err);
        t('key');
    });

module.exports = {
    i18next,
    middleware
};