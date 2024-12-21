import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // 1. Retrieve the token from the Authorization header
  const token = req.header('Authorization')?.split(' ')[1]; // Expected format: "Bearer <token>"

  // 2. If no token exists, respond with a 401 Unauthorized status
  if (!token) {
    return res.status(401).json({ message: 'Access Denied: No Token Provided' });
  }

  // 3. Verify the token using the secret key
  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    if (err) {
      // If token is invalid or expired, respond with a 403 Forbidden status
      return res.status(403).json({ message: 'Invalid Token' });
    }

    // 4. Attach the user data from the token to the request object
    if (typeof user !== 'string' && user !== undefined) {
      req.user = user as JwtPayload;
    }

    // 5. Proceed to the next middleware or route handler
    next();
    return;
  });

  return;
};
