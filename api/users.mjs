        import express from 'express';
        import User from '../models/user.js';
        import jwt from 'jsonwebtoken';
        import 'dotenv/config';

        let route = express.Router();

        let authenticate = (req, res, next) => {
            const authHeader = req.headers.authorization;

            if (!authHeader) {
                return res.status(401).json({
                    error: true,
                    message: 'Unauthorized access, please login first!'
                });
            }

            const [bearer, token] = authHeader.split(' ');

            if (bearer !== 'Bearer' || !token) {
                return res.status(401).json({
                    error: true,
                    message: 'Invalid authorization format.  Use "Bearer <token>"'
                });
            }

            jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).json({
                        error: true,
                        message: 'Invalid or expired token.'
                    });
                }

                req.user = decoded; // Store the decoded user information in the request
                console.log('User authenticated');
                next();
            });
        };


        route.delete('/', authenticate, (req, res) => {
            res.send('users api working!');
        });

        export default route;
        