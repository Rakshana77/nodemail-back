import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import UserModel from './models/User.js'; 
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt'; 

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:5173"],
    credentials: true
})); 

mongoose.connect('mongodb://127.0.0.1:27017/employee')
    .then(() => {
        console.log("Database connected");
    })
    .catch(err => {
        console.error("Database connection error:", err);
    });

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await UserModel.create({ name, email, password: hashedPassword });
        res.json(user);
    } catch (err) {
        res.json({ error: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await UserModel.findOne({ email });
        if (user) {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (isPasswordValid) {
                const accessToken = jwt.sign({ email: email }, "jwt-access-token-secret-key", { expiresIn: '1m' });
                const refreshToken = jwt.sign({ email: email }, "jwt-refresh-token-secret-key", { expiresIn: '5m' });

                res.cookie('accessToken', accessToken, { maxAge: 60000 });
                res.cookie('refreshToken', refreshToken, { maxAge: 300000, httpOnly: true, secure: true, sameSite: 'strict' });
                return res.json({ Login: true });
            } else {
                return res.json({ Login: false, Message: "Invalid Password" });
            }
        } else {
            return res.json({ Login: false, Message: "No record found" });
        }
    } catch (err) {
        res.json({ error: err.message });
    }
});

const verifyUser = (req, res, next) => {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) {
        if (renewToken(req, res)) {
            next();
        } else {
            res.status(401).json({ valid: false, message: "Unauthorized" });
        }
    } else {
        jwt.verify(accessToken, 'jwt-access-token-secret-key', (err, decoded) => {
            if (err) {
                return res.json({ valid: false, message: "Invalid Token" });
            } else {
                req.email = decoded.email;
                next();
            }
        });
    }
};

const renewToken = (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    let exist = false;
    if (!refreshToken) {
        return res.json({ valid: false, message: "No Refresh Token" });
    } else {
        jwt.verify(refreshToken, 'jwt-refresh-token-secret-key', (err, decoded) => {
            if (err) {
                return res.json({ valid: false, message: "Invalid Refresh Token" });
            } else {
                const accessToken = jwt.sign({ email: decoded.email }, "jwt-access-token-secret-key", { expiresIn: '1m' });
                res.cookie('accessToken', accessToken, { maxAge: 60000 });
                exist = true;
            }
        });
    }
    return exist;
};

app.get('/dashboard', verifyUser, (req, res) => {
    return res.json({ valid: true, message: "Authorized" });
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.send({ status: "user not exist" });
        }
        const token = jwt.sign({ id: user._id }, "jwt_secret_key", { expiresIn: "2d" });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'sonarakshana@gmail.com',
                pass: 'rzyr btai jpio oeht' // Replace with the generated app password
            },
            tls: {
                rejectUnauthorized: false // Add this to bypass self-signed certificate error
            }
        });

        const mailOptions = {
            from: 'sonarakshana@gmail.com',
            to: email,
            subject: 'Password Reset',
            text: `http://localhost:5173/reset-password/${user._id}/${token}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log('Error:', error);
                return res.json({ Status: "fail", Error: error.message });
            } else {
                console.log(info)
                return res.send({ Status: "success" });
            }
        });
       
    } catch (err) {
        res.json({ error: err.message });
    }
});
// app.post('/reset-password/:id/:token', (req, res) => {
//     const {id, token} = req.params
//     const {password} = req.body

//     jwt.verify(token, "jwt_secret_key", (err, decoded) => {
//         if(err) {
//             return res.json({Status: "Error with token"})
//         } else {
//             bcrypt.hash(password, 10)
//             .then(hash => {
//                 UserModel.findByIdAndUpdate({_id: id}, {password: hash})
//                 .then(u => res.send({Status: "Success"}))
//                     .catch(err => res.send({ Status: err }))
                
//             })
//             .catch(err => res.send({Status: err}))
//         }
//     })
// })
app.post('/reset-password/:id/:token', async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;

    try {
        const decoded = jwt.verify(token, "jwt_secret_key");
        const hash = await bcrypt.hash(password, 10);
        await UserModel.findByIdAndUpdate(id, { password: hash });
        res.send({ Status: "Success" });
    } catch (err) {
        res.send({ Status: err.message || "Error with token" });
    }
});

app.listen(3001, () => {
    console.log("Server is Running");
});
