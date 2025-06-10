import express from 'express';
import Joi from 'joi';
import User from '../models/user.mjs';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const route = express.Router();

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'dev'] } })
    .required(),
  password: Joi.string().min(6).required(),
  age: Joi.number().integer().min(1).required(),
});
const loginSchema = Joi.object({
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'dev'] } })
    .required(),
  password: Joi.string().min(6).required(),
});

route.post('/login', async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: true,
        message: error.details[0].message,
      });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        error: true,
        message: 'User not found!',
      });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({
        error: true,
        message: 'Invalid email or password!',
      });
    }

    const payload = { id: user._id, email: user.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({
      error: false,
      message: 'Login successful!',
      token,
      data: {
        id: user._id,
        email: user.email,
        username: user.username,
        age: user.age,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: 'Internal server error!',
    });
  }
});

route.post('/register', async (req, res) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: true,
        message: error.details[0].message,
      });
    }

    const { username, email, age, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        error: true,
        message: 'User already exists with this email!',
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    let newUser = new User({
      username,
      email,
      age,
      password: hashedPassword,
    });

    newUser = await newUser.save();

    res.status(200).json({
      error: false,
      message: 'User registered successfully!',
      data: newUser,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: 'Internal server error!',
    });
  }
});

export default route;
