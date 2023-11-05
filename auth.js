require('dotenv').config()
const app = require('./app');
const passport = require('passport');
const jwt = require("jsonwebtoken");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
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

        const user = { email, name };
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