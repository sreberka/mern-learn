const {Router} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Incorrect Email').isEmail(),
        check('password', 'Minimum 6 symbols').isLength({min: 6})
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)
        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect registration data'
            })
        }
        const {email, password} = req.body;
        const candidate = await User.findOne({email})
        if (candidate) {
            return res.status(400).json({ message: 'User exists' })
        }

        const hashedpassword = await bcrypt.hash(password, 12);
        const user = new User({email, password: hashedpassword})

        await user.save()

        res.status(201).json({message: 'The user was created'})

    } catch (e) {
        res.status(500).json({ message: 'Something went wrong' })
    }
})

// /api/auth/login
router.post('/login',
    [
        check('email', 'Incorrect Email').normalizeEmail().isEmail(),
        check('password', 'Minimum 6 symbols').exists()
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)
        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect sign in data'
            })
        }

        const {email, password} = req.body

        const user = await User.findOne({ email})

        if(!user) {
            return res.status(400).json({message: 'User not found'})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch) {
            return res.status(400).json({message: 'wrong password'})
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.status(200).json({token, userId: user.id})

    } catch (e) {
        res.status(500).json({ message: 'Something went wrong' })
    }
})

module.exports = router