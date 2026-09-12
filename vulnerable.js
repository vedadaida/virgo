// vulnerable.js
import express from 'express';
const app = express();

// Vulnerability 1: Hardcoded credentials / secret
const API_SECRET_KEY = "super-secret-key-12345!@#";

app.get('/run', (req, res) => {
    const code = req.query.code;
    
    // Vulnerability 2: Dynamic code execution via eval (Remote Code Execution risk)
    // eval() runs the user-supplied string as JavaScript code.
    const result = eval(code);
    
    res.send(`Result: ${result}`);
});

app.get('/login', (req, res) => {
    const { username, password } = req.query;
    
    // Check key
    if (password === API_SECRET_KEY) {
        res.send("Welcome back!");
    } else {
        res.send("Access denied.");
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
