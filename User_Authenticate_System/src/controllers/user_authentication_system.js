const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const fs = require('fs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const timeout = require('connect-timeout');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mongoose = require('mongoose');
const User = require('../models/User');
const cron = require('node-cron');
const dotenv = require('dotenv');
const app = express();
const SESSION_TIMEOUT = 10 * 60 * 1000;

// Load environment variables from .env file
dotenv.config();
// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', '../views');

// Load Gmail user and pass from environment variables
const gmailUser = process.env.GMAIL_USER;
console.log(gmailUser);
const gmailPass = process.env.GMAIL_PASS;
console.log(gmailPass);

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/users', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Failed to connect to MongoDB', err));

    // Use express-session middleware
    const sessionMiddleware = session({
        secret: crypto.randomBytes(16).toString('hex'),
        resave: false,
        saveUninitialized: false,
        mongooseConnection: mongoose.connection, // Use the existing mongoose connection
        collection: 'sessions', // Specify the collection name for sessions
        ttl: 600,
        cookie: {
            maxAge: 600000 // Set cookie expiration time to 10 minutes (600000 milliseconds)
        }
    });
    app.use(sessionMiddleware);

    // Middleware to set no-cache headers for all responses
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// Routes
app.get('/', (req, res) => {
    const { email, firstName, lastName, password} = req.body;
    const errorMessage = "";
    res.render('registration',{errorMessage,email, firstName, lastName, password});
});
// Verification page route
app.get('/verify', (req, res) => {
    const token = req.query.token;
    const forgotPassword = req.query.forgotPassword;
    const errorMessage = "";
    res.render('verification', {errorMessage, token, forgotPassword});
});
// Route to serve user homepage
app.get('/user-homepage',isAuthenticated, checkSessionTimeout, (req, res) => {
    // Render the user homepage view
    res.render('user-homepage');
});
// Route to serve login form
app.get('/login', (req, res) => {
    const {email, password} = req.body;
    const errorMessage = "";
    res.render('login', {errorMessage, email, password});
});
// Route to handle redirection to registration page
app.get('/login/register', (req, res) => {
    const { email, firstName, lastName, password} = req.body;
    const errorMessage = "";
    res.render('registration',{errorMessage,email, firstName, lastName, password});
    res.redirect('/register'); // Redirects to the registration page
});
// Route to serve registration form
app.get('/register', (req, res) => {
    const { email, firstName, lastName, password} = req.body;
    const errorMessage = "";
    res.render('registration',{errorMessage,email, firstName, lastName, password});
});

// Route to serve forgot password form
app.get('/forgot-password', (req, res) => {
    const {email} = req.body;
    const errorMessage = "";
    res.render('forgot-password',{email, errorMessage});
});
// Route to serve password reset form
app.get('/reset-password', (req, res) => {
    const { newPassword , confirmPassword } = req.body;
    const errorMessage = "";
    // Render the password reset form
    res.render('reset-password', {errorMessage, newPassword, confirmPassword });
});

app.post('/register', async (req, res) => {
    const { email, firstName, lastName, password } = req.body;
    const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.render('registration', { errorMessage: 'Password must be at least 8 characters long and include symbols and numbers',email, firstName, lastName, password});
    }
    
    try {

        const existingUser = await User.findOne({email});
        if (existingUser && existingUser.isVerified) {
            const { email, firstName, lastName} = req.body;
            return res.render('registration', { errorMessage: 'User already existed please login',email, firstName, password, lastName});
        }else if(existingUser){
            const token = generateVerificationToken(email);
            const decodedToken = decodeVerificationToken(token);
            const verificationToken = decodedToken.token;
            const newUser = new User({
                email,
                firstName,
                lastName,
                password,
                verificationToken
            });
            newUser.isVerified = false;
            await newUser.save();
            await sendVerificationEmail(email, decodedToken.token, firstName);
            res.redirect(`/verify?token=${token}`);
        }else {
            const token = generateVerificationToken(email);
            const decodedToken = decodeVerificationToken(token);
            const verificationToken = decodedToken.token;
            const newUser = new User({
                email,
                firstName,
                lastName,
                password,
                verificationToken
            });
            newUser.isVerified = false;
            await newUser.save();
            await sendVerificationEmail(email, decodedToken.token, firstName);
            res.redirect(`/verify?token=${token}&&sessionId=${req.session.id}`);
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Error registering user');
    }
});

// Verification process route
app.post('/verify', async (req, res) => {
    const sessionId = req.session.id;
    const {verificationToken, token, forgotPassword} = req.body;
    try {
        const user = await User.findOne({verificationToken});
        if (!user) {
            const errorMessage = 'Invalid Verification Token';
             // Render the verify view with errorMessage
            res.render('verification', {errorMessage, token });
           
        } else {
            const decodedToken = decodeVerificationToken(token);
            if (decodedToken.token == verificationToken) {
            // Check if the token has expired
            if (isTokenExpired(decodedToken.expiresAt)) {
                const errorMessage='Token has expired';
                res.render('verification', {errorMessage, token });
            } else{
                // Mark the user's email as verifies
                user.isVerified = true;
                await user.save();
                if (forgotPassword === 'true') {
                    res.redirect('/reset-password');
                } else {
                    // Redirect the user to their homepage upon successful authentication
                    res.redirect('/user-homepage?sessionId=${sessionId}');
                }
            }
        }                      
        }
    } catch (error) {
        console.error('Error verifying email:', error);
        res.status(500).send('Error verifying email');
    }
});
// Route to handle user authentication
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Find the user by email
        const user = await User.findOne({ email });

        // If user not found or password is incorrect, render login page with error message
        if (!user || user.password !== password) {
            return res.render('login', { errorMessage: 'Invalid email or password' ,email, password});
        }
        req.session.userId = user.email;
        const token = generateVerificationToken(email);
        const decodedToken = decodeVerificationToken(token);
        user.verificationToken = decodedToken.token;
        await user.save();
        await sendVerificationEmail(email, decodedToken.token, user.firstName);
        res.redirect(`/verify?token=${token}&&sessionId=${req.session.id}`);       
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Error during login');
    }
});
// Route to handle password reset request
app.post('/forgot-password', async (req, res) => {
    const { email} = req.body;
    try {
        // Find the user by email
        const user = await User.findOne({ email });

        // If user not found or password is incorrect, render login page with error message
        if (!user) {
            return res.render('forgot-password', { errorMessage: 'Invalid email' ,email});
        }
        const token = generateVerificationToken(email);
        const decodedToken = decodeVerificationToken(token);
        user.verificationToken = decodedToken.token;
        await user.save();
        await sendVerificationEmail(email, decodedToken.token, user.firstName);
        res.redirect(`/verify?forgotPassword=true&&token=${token}&&verifyEmail=true`);       
    } catch (error) {
        console.error('Error during resetting password:', error);
        res.status(500).send('Error during resetting password');
    }
    
});
// Route to handle password reset submission
app.post('/reset-password', async (req, res) => {
    const { newPassword, confirmPassword } = req.body;
    if (newPassword != confirmPassword) {
        return res.render('reset-password', { errorMessage: 'Confirm password is Different', newPassword, confirmPassword});
    }else{
        res.render('reset-password-success', { message: 'Password changed successfully. Redirecting to login page...'});
    }
});
// Route to serve user homepage
app.get('/user-homepage',isAuthenticated, checkSessionTimeout, async (req, res) => {
    // Check if user is authenticated
    if (!req.session.userId) {
        // Redirect to login page if not authenticated
        return res.redirect('/login');
    }else{
        // Render the user homepage view
        res.render('user-homepage&&sessionId=$'+req.session.id);
    }
});
app.get('/logout',  async (req, res) => {
    // Destroy the session
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            res.status(500).send('Error logging out');
        } else {
            // Redirect to the login page after successful logout
            res.redirect('/login');
        }
    });
});
// Start node-cron scheduler to delete expired user records every 10 minutes
cron.schedule('*/10 * * * *', async () => {
    try {
        // Find user records where verification token has expired
        const expiredUsers = await User.find({isVerified: false });
        // Extract email addresses of expired users
        const expiredEmails = expiredUsers.map(user => user.email);
        // Delete expired user records by email
        await User.deleteMany({ email: { $in: expiredEmails } });
        console.log(`Expired user records deleted (${expiredUsers.length}) at ${new Date().toLocaleString()}`);
    } catch (error) {
        console.error('Error deleting expired user records:', error);
    }
});
// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


function generateVerificationToken(email) {
    const token = tokenGeneration();
   // Calculate expiration time (5 minutes from now)
   const expirationTime = Date.now() + (5 * 60 * 1000); // 5 minutes in milliseconds

   // Combine token and expiration time in the payload
   const payload = {
       token: token,
       email: email,
       expiresAt: expirationTime
   };
   // Convert payload to a JSON string
   const tokenString = JSON.stringify(payload);
   // Encode the token string to base64
   const base64Token = Buffer.from(tokenString).toString('base64');
   return base64Token;
}
function tokenGeneration() {
    const tokenLength = 6;
    const randomBytes = crypto.randomBytes(tokenLength);
    const token = randomBytes.toString('hex');
    // Ensure the token contains both letters and numbers
    const alphanumericToken = token.replace(/\W/g, '');
    // If the alphanumeric token is shorter than the required length, recursively call the function to generate a new token
    if (alphanumericToken.length < tokenLength) {
        return tokenGeneration();
    }
    // Return the first 10 characters of the alphanumeric token
    return alphanumericToken.substring(0, tokenLength);
}
async function sendVerificationEmail(email, verificationToken, firstName) {
    try {
        const htmlFilePath = '/Users/naveenkrishna/Desktop/User_Authenticate_System/src/templates/email_content.html';
        // Read the HTML email template content asynchronously
        fs.readFile(htmlFilePath, 'utf8', (err, htmlContent) => {
            if (err) {
                console.error('Error reading HTML file:', err);
                return;
            }
            // Replace the verificationToken placeholder with the actual token
            const formattedHtmlContent = htmlContent.replace('{{firstName}}', firstName).replace('{{verificationToken}}', verificationToken);
            // Create a transporter using nodemailer
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'snaveenkrishna157@gmail.com', // your Gmail address
                    pass: 'ysjhcetorohrckat' // your Gmail password or application-specific password
                }
            });
            // Send email with the modified HTML content
            transporter.sendMail({
                from: 'User Autherization Services',
                to: email,
                subject: 'Email Verification',
                html: formattedHtmlContent
            }, (error, info) => {
                if (error) {
                    console.error('Error sending verification email:', error);
                } else {
                    console.log('Verification email sent:', info.response);
                }
            });
        });
    } catch (error) {
        console.error('Error sending verification email:', error);
    }
}
function decodeVerificationToken(verificationToken) {
    try {
        // Decode the base64 token
        const decodedTokenString = Buffer.from(verificationToken, 'base64').toString('utf-8');       
        // Parse the JSON string to get the payload
        const payload = JSON.parse(decodedTokenString);       
        // Extract token, email, and expiration time from the payload
        const token = payload.token;
        const email = payload.email;
        const expiresAt = payload.expiresAt;
        // Return an object containing the token, email, and expiration time
        return { token, email, expiresAt };
    } catch (error) {
        // If decoding or parsing fails, return null or handle the error accordingly
        return null;
    }
}
// Define middleware function to check authentication
function isAuthenticated(req, res, next) {
    // Check if user is authenticated
    if (req.session.userId) {
        // Reset session timeout
        req.session.lastActive = Date.now();
        next();
    } else {
        // User is not authenticated, redirect to login page
        res.redirect('/login');
    }
}
function isTokenExpired(expiresAt) {
    // Get the current time
    const currentTime = Date.now();   
    // Check if the expiration time has passed
    return currentTime > expiresAt;
}
// Middleware to check session timeout
function checkSessionTimeout(req, res, next) {
    if (req.session.lastActive && (Date.now() - req.session.lastActive) > SESSION_TIMEOUT) {
        // Session has expired, destroy session and redirect to login with a message
        req.session.destroy(() => {
            res.redirect('/login?sessionExpired=true');
        });
    } else {
        // Reset session timeout
        req.session.lastActive = Date.now();
        next();
    }
}

