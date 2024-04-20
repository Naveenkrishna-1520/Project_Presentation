const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new mongoose.Schema({
    email: String,
    firstName: String,
    lastName: String,
    password: String,
    verificationToken: String,
    isVerified: Boolean
});

const User = mongoose.model('User', userSchema);

module.exports = User;
