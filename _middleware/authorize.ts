import { expressjwt as jwt } from 'express-jwt';
import config from '../config.json';
import db from '../_helpers/db';

const { secret } = config;

export default function authorize(roles: any = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return [
        // The jwt middleware authenticates the token and populates req.auth
        jwt({ secret, algorithms: ['HS256'] }),

        async (req: any, res: any, next: any) => {
            // CHANGE: Use req.auth instead of req.user
            if (!req.auth) return res.status(401).json({ message: 'Unauthorized' });

            const account = await db.Account.findByPk(req.auth.id);

            if (!account || (roles.length && !roles.includes(account.role))) {
                return res.status(401).json({ message: 'Unauthorized' });
            }

            // Map req.auth to req.user so the rest of your controllers still work
            req.user = account; 
            req.user.role = account.role;
            
            const refreshTokens = await account.getRefreshTokens();
            req.user.ownsToken = (token: any) => !!refreshTokens.find((x: any) => x.token === token);
            
            next();
        }
    ];
}