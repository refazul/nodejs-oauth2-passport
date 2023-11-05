// app.js
require('dotenv').config()
const express = require('express');
const session = require("express-session");
const app = express();

app.use(session({ secret: process.env.JWT_SECRET, resave: false, saveUninitialized: false }));

module.exports = app; // Export the app object
