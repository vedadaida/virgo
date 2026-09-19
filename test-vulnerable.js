// A deliberately insecure file to test VIRGO's GitHub PR scanning
const express = require('express');
const app = express();

// Hardcoded secret - VIRGO should catch this!
const API_SECRET_KEY = 'super-secret-password-1234';

app.get('/search', (req, res) => {
    const userInput = req.query.q;

    // Dangerous eval() - VIRGO should catch this!
    const result = eval(userInput);
    res.json({ result });
});

app.listen(3000);
