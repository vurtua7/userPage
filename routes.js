var express = require("express");
var User = require("./models/user");
var router = express.Router();

router.use((req, res, next) =>
{
    res.locals.currentUser = req.user;
    res.locals.errors = req.flash("error");
    res.locals.infos = req.flash("info");
    next();
});

router.get("/", (req, res, next) =>
{
    User.find().sort({createdAt:"descending"}).exec((e, users) =>
    {
        if(e) return next(e);
        res.render("index", {users: users})
    });
});
module.exports = router;