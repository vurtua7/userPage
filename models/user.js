var bcrypt = require("bcrypt-nodejs");
var mongoose = require('mongoose');

var SALT_FACTOR = 10;

var userSchema = mongoose.Schema({
    username:{type:String, requred:true, unique:true},
    password:{type:String, requred:true},
    createdAt:{type:Date, default: Date.now},
    displayName: String,
    bio: String
});

var noop = function(){};

userSchema.pre("save", (done) =>
{
    var user = this;
    if(!user.isModified("password"))
    {
        return done();
    }
    bcrypt.genSalt(SALT_FACTOR, (e,salt) =>
    {
        if(e) return done(e);
    });
    bcrypt.hash(user.password, salt, noop, (e, hPass) =>
    {
        if(e) return done(e);
        user.password = hPass;
        done();
    });
});

userSchema.methods.checkPassword = (guess, done) =>
{
    bcrypt.compare(guess, this.password, (e,isMatch) =>
    {
        done(e,isMatch);
    });
};

userSchema.methods.name = function(){
    return this.displayName || this.username;
};

var User = mongoose.model("User", userSchema);
module.exports = User;