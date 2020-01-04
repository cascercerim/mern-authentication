const express = require('express');
//router allows us to set routes to get/post etc requests
const router = express.Router();
//imports gravatar ackage that will link the user's profile picure to email image
const gravatar = require('gravatar');
//will allow us to encrypt the password
const bcrypt = require('bcryptjs');
//webtoken that will allow us to verify the user on login
const jwt = require('jsonwebtoken');
//import secret from config
const config = require('config');
//import express-validator which will allow us to add a field (such as username) to determine criteria such as minimum length, if there are errors send a response 
const { check, validationResult } = require('express-validator');

// import the user model
const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  public
//because of express-validator, brackets are placed after the route with parameter to check and error message
router.post('/',
  [
    check('name', 'name is required')
      .not()
      .isEmpty(),
    check('email', 'please include a valid email')
      .isEmail(),
    check('password', 'please enter a password with 6 or more characters')
      .isLength({ min: 6 })
  ],
  async (req, res) => {

    //checks if there are errors and returns the result
    const errors = validationResult(req);
    //if there ARE errors, these will be sent back as a 400 message
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    //the request being parsed from the body get saved as the below variables
    const { name, email, password } = req.body;


    try {
      // check if the user exists 
      // takes in a field (in this case an email) anch checks it against database
      let user = await User.findOne({ email });

      //if the user exists send back 400 status & an error message
      if (user) {
        return res.status(400).json({ errors: [{ msg: 'user already exists' }] });
      };

      //if the user is not found then account can be created...
      //get the url for the user's 'gravatar' which is from their email
      const avatar = gravatar.url(email, {
        s: '200', //default size
        r: 'pg',
        d: 'mm' //default image / user icon
      });

      //the information from the variables (above, req.body) are saved to a new User schema 
      user = new User({
        name,
        email,
        avatar,
        password
      });

      //encrypt password (before saving the above object to the actual database)
      const salt = await bcrypt.genSalt(10);

      //this creates a hash that will update the password in the user object to encrypted
      user.password = await bcrypt.hash(password, salt);

      //save user to the database
      await user.save();

      //return jsonwebtoken so that the user can be logged in right away when they register
      //mongoose allows us to use id instead of _id 
      const payload = {
        user: {
          //this id is obtained from the user object saved to the schema (which creates an id) 
          id: user.id
        }
      };


      //pass the payload, secret, expiration and get the token (if no error)
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 3600000 },
        (err, token) => {
          if (err) throw err;
          // await res.send({token});
          return res.json({ token });
        });

    } catch (err) {
      //if somethin goes wrong...
      console.log(err.message);
      res.status(500).send('server error');
    }

    // //send the token back to the client - will send it in the header to access protected routes (connected to user id)
  });


module.exports = router;