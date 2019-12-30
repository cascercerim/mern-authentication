const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

// user model
const User = require('../../models/User')

// @route   GET api/auth
// @desc    test route
// @access  public

router.get('/', auth, async (req, res) => {
try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
} catch(err) {
    console.error(err.message);
    res.status(500).send('server error');
}
});

// @route   POST api/auth
// @desc    Authenticate user and get token
// @access  public
router.post('/',
    [
        check('email', 'please include a valid email')
        .isEmail(),
        check('password',
        'password is required'
        ).exists()
    ], 
    async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    
    try {
    
    let user = await User.findOne({ email });
    
    if(!user) {
        return res
        .status(400)
        .json({ errors: [ { msg: 'invalid credentials' }]});
    };


    const payload = {
        user: {
            
            id: user.id
        }
    };


    const isMatch = await bcrypt.compare(password, user.password);

    if(!isMatch) {
        return res
        .status(400)
        .json({ errors: [ { msg: 'invalid credentials' }]});
    };

     //pass the payload, secret, expiration and get the token (if no error)
    jwt.sign(
        payload, 
        config.get('jwtSecret'),
        { expiresIn: 3600000 },
        (err, token) => {
            if (err) throw err;
             //send the token back to the client - will send it in the header to access protected routes (connected to user id)
            return res.json({ token });
    });

    } catch(err) {
        //if somethin goes wrong...
        console.log(err.message);
        res.status(500).send('server error');
    };

});


module.exports = router;