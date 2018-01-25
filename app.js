var express = require("express");
var mongoose = require("mongoose");
var path = require("path");
var bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
var session = require("express-session");
var flash = require("connect-flash");
var routes = require("./routes");

var app = express();

mongoose.connect("mongodb://localhost:27017/test");
app.set("port", process.env.PORT || 3000);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended:false}));
app.use(cookieParser());
app.use(session({
    secret:"itsASecretToEveryone",
    resave:true,
    saveUninitialized:true
}));

app.use(flash());
app.use(routes);

app.listen(app.get("port"), ()=>
{
    console.log("Server started on port " + app.get("port"));
});