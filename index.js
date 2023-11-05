// index.js

const app = require('./app');
require("./cookie");
require("./auth");
const {getName, verifyToken} = require("./middleware");

app.get('/', getName, (req, res) => {
    res.send(`Hello ${req.displayName}`);
});

app.get('/api/products', verifyToken, (req, res) => {
    res.json({ products: ['product1', 'product2', 'product3'] });
});

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});