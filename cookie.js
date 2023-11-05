const cookieParser = require("cookie-parser");
const app = require('./app');
app.use(cookieParser());

getCookie = function(req, res, name) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return req.cookies[name] || req.header(name) || '';//res.send('No cookies found.');
    }

    // Split the cookies into an array
    const cookieArray = cookies.split(';').map((cookie) => cookie.trim());

    // Create an object to store the cookie key-value pairs
    const cookieData = {};

    for (const cookie of cookieArray) {
        const [key, value] = cookie.split('=');
        cookieData[key] = value;
    }
    return cookieData[name] || req.cookies[name] || req.header(name) || '';
}

module.exports = { getCookie }