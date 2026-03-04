export function fixedEncodeURIComponent(str) {
    return encodeURIComponent(str).replace(/[!'()*\-_.~]/g, function (c) {
        return '%' + c.charCodeAt(0).toString(16);
    });
}