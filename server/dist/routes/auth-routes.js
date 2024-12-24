import { Router } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import authRoutes from './auth-routes'; // Add this line to import authRoutes
import { authenticateToken } from '../middleware/auth.js';
import apiRoutes from './index.js'; // Add this line to import apiRoutes
export const login = async (req, res) => {
    // TODO: If the user exists and the password is correct, return a JWT token
    // Extract username and password from the request body
    const { username, password } = req.body;
    // Find the user in the database by username
    const user = await User.findOne({
        where: { username },
    });
    // If the user is not found, send an authentication failed response
    if (!user) {
        return res.status(401).json({ message: 'Authentication failed' });
    }
    // Compare the provided password with the stored hashed password
    const passwordIsValid = await bcrypt.compare(password, user.password);
    // If the password is invalid, send an authentication failed response
    if (!passwordIsValid) {
        res.status(401).json({ message: 'Authentication failed' });
    }
    // Get the secret key from the environment vairables
    const secretKey = process.env.JWT_SECRET_KEY || '';
    // Generate a JWT token for the authentiated user
    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    // Send the token as a JSON response
    return res.json({ token });
};
const router = Router();
// POST /login - Login a user
router.use('/auth', authRoutes);
router.use('/api', authenticateToken, apiRoutes);
export default router;
