import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    // 1. Check if the user exists in the database
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // 2. Verify the password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // 3. Generate a JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username }, // Payload (you can add other info as needed)
      process.env.JWT_SECRET as string, // Secret key for signing the JWT
      { expiresIn: '1h' } // Optional: Set an expiration time for the token
    );

    // 4. Return the token in the response
    return res.json({ token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
