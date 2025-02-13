'use strict';

var express = require('express');
var controller = require('./user.js');
var router = express.Router();

router.post('/register', controller.register);
router.post('/login', controller.login);


module.exports = router;