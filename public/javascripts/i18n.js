import i18next from 'i18next';
import Backend from 'i18next-fs-backend';
import middleware from 'i18next-http-middleware';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
        if (err) {
            return console.log('something went wrong loading', err);
        }
    });

export default {
    i18next,
    middleware
};