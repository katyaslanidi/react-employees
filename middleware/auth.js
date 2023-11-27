const { prisma } = require('../prisma/prisma-client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

const auth = async (req, res, next) => {
    try {
        let token = req.headers.authorization?.split(' ')[1];

        const decoded = jwt.verify(token, JWT_SECRET);

        const user = await prisma.user.findUnique({
            where: {
                id: decoded.id
            }
        });

        req.user = user;

        next();
    } catch (error) {
        res.status(401).json({ message: 'Не авторизован' });
    }
}

module.exports = {
    auth
}