// routes/api/User/user.js
const { Users } = require('../../../schema/user');
const logger = require('../../../logs/logger');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

exports.register = async function (req, res) {
	try {
		let { userName, email, password, firstName, lastName, userRole, mobile } = req.body;

		if (!userName || !password || !email) {
			return res.status(400).send({ success: false, message: 'These fields are required: UserName, Password, Email' });
		}

		const existingUser = await Users.findOne({ userName: userName });

		if (existingUser) {
			return res.status(400).send({ success: false, message: 'Username already exists' });
		}

		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		const newUser = new Users({ userName, email, password: hashedPassword, firstName, lastName, userRole, mobile });
		await newUser.save();
		res.header('X-AT-SessionToken', `Bearer ${token}`);
		return res.status(201).send({ success: true, message: 'User registered successfully' });

	} catch (err) {
		console.error(`api/user/register`, err);
		logger.RaiseLogEvent('api/user/register', 'error', err, `Data ${JSON.stringify(req.body)}`);
		return res.status(500).send({ success: false, error: 'Error in processing your request.' });
	}
};


exports.login = async function (req, res) {
	try {
		let { userName, password } = req.body;

		if (!userName || !password) {
			return res.status(400).send({ success: false, message: 'All fields are required' });
		}

		let User = await Users.findOne({ userName: userName });

		if (!User) {
			return res.status(400).send({ success: false, message: 'User not found' });
		}

		let checkPassword = await bcrypt.compare(password, User.password);

		if (!checkPassword) {
			return res.status(400).send({ success: false, message: 'Incorrect password' });
		}

		// Generate JWT
		let token = jwt.sign({ id: User.id, userRole: User.userRole, userName: User.userName }, 'secretKey', { expiresIn: '8h' });
		return res.status(201).send({ success: true, message: token });

	} catch (err) {
		console.log(`api/user/login`, err);
		logger.RaiseLogEvent('api/user/login', 'error', err, `Data ${JSON.stringify(req.body)}`);
		return res.send({ success: false, error: 'Error in processing your request.' });
	}
}