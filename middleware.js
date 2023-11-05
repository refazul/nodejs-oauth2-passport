// middleware.js
const {getCookie} = require("./cookie");
const jwt = require("jsonwebtoken");

verifyToken = function(req, res, next) {
    const authorization = getCookie(req, res, 'Authorization');
    jwt.verify(authorization, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        // Access is granted
        next();
    });
}
getName = function(req, res, next) {
    const authorization = getCookie(req, res, 'Authorization');
    jwt.verify(authorization, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            req.displayName = 'Guest';
        } else {
            req.displayName = decoded.name;
        }
        next();
    });
}

module.exports = { verifyToken, getName }