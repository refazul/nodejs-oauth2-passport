require('dotenv').config()
const express = require('express');
const cookieParser = require("cookie-parser");
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
// Google OAuth2 configuration
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL, // Redirect URI
        },
        (accessToken, refreshToken, profile, done) => {
            // Save the access token and user information (if needed)
            // In a real application, you'd store this data securely
            const user = { accessToken, profile };
            return done(null, user);
        }
    )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

const app = express();
app.use(cookieParser());

app.use(session({ secret: process.env.JWT_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
    '/auth/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Successful authentication, redirect or respond as needed.
        const access_token = req.user.accessToken;
        const email = req.user.profile.emails[0].value;
        const name = req.user.profile.displayName;

        const user = req.user;
        const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });

        const cookieOptions = {
            maxAge: 7 * 24 * 60 * 60 * 1000, // Cookie expiration time in milliseconds (e.g., 7 days).
            httpOnly: true, // Ensure the cookie is accessible only via HTTP.
            sameSite: 'strict', // Enforce same-site cookie policy.
        };
        // Set the JWT in a cookie.
        res.cookie('Authorization', token, cookieOptions);
        res.redirect('/');
    }
);

// Custom middleware for verifying Google access token
function verifyToken(req, res, next) {
    const authorization = req.cookies['Authorization'] || getCookie(req, res, 'Authorization') || req.header('Authorization');
    jwt.verify(authorization, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        // Access is granted
        next();
    });
}
function getName(req, res, next) {
    const authorization = req.cookies['Authorization'] || getCookie(req, res, 'Authorization') || req.header('Authorization');
    jwt.verify(authorization, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            req.displayName = 'Guest';
        } else {
            req.displayName = decoded.profile.displayName;
        }
        next();
    });
}

app.get('/', getName, (req, res) => {
    res.send(`Hello ${req.displayName}`);
});

app.get('/api/products', verifyToken, (req, res) => {
    res.json({ products: ['product1', 'product2', 'product3'] });
});

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});



// Optional
function getCookie(req, res, name) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return '';//res.send('No cookies found.');
    }

    // Split the cookies into an array
    const cookieArray = cookies.split(';').map((cookie) => cookie.trim());

    // Create an object to store the cookie key-value pairs
    const cookieData = {};

    for (const cookie of cookieArray) {
        const [key, value] = cookie.split('=');
        cookieData[key] = value;
    }
    return cookieData[name];
}