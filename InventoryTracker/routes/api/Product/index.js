'use strict';

var express = require('express');
var controller = require('./product');
var router = express.Router();
const jwt = require('jsonwebtoken');


// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
	const token = req.headers['authorization'];
	if (!token) {
		return res.status(400).send({ success: false, error: 'Access Denied' });
	};
	// Verify the token
	jwt.verify(token, "secretKey", (err, decoded) => {
		if (err) {
			console.log(err)
			return res.status(403).send({ success: false, message: 'Invalid or expired token' });
		}

		req.user = decoded;

		next();
	});
};

router.post('/create', authenticateToken, controller.create);
router.get('/list', authenticateToken, controller.list);
router.put('/update/:id', authenticateToken, controller.update);
router.delete('/delete/:id', authenticateToken, controller.delete);

module.exports = router;