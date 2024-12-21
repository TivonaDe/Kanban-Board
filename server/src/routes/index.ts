import { Router, Response, Request, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import authRoutes from './auth-routes.js';
import apiRoutes from './api/index.js';
import { authenticateToken} from '../middleware/auth.js';

const router = Router();

router.use('/auth', authRoutes);
// TODO: Add authentication to the API routes

router.use('/api', authenticateToken, apiRoutes);

interface AuthenticatedRequest extends Request {
  user?: any;
}

export function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers['authorization'] as string | undefined;
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
      res.sendStatus(401);
    } else {
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string, (err: any, user: any) => {
        if (err) {
          res.sendStatus(403);
        } else {
          req.user = user;
          next();
        }
      });
    }
  }
  

export default router;
