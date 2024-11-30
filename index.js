const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const bodyParser = require("body-parser")
const Usermodel = require("./models/userschema")
const crypto = require('crypto');
const JWT = require("jsonwebtoken")
const Mail = require("nodemailer/lib/mailer")
const PORT = 5000

require('dotenv').config();

const app = express()

const cors = require('cors');
app.use(cors());
app.use(bodyParser.json());
const jwt_secret = crypto.randomBytes(32).toString('hex');

let personusername = ""

function generatetoken(user) {
    return JWT.sign({ username: user.username, email: user.email }, jwt_secret, { expiresIn: '1h' })
}

const sendEmail = async (to, subject, text, email) => {
    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: process.env.MAIL_PORT,
        secure: false,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.MAIL_USER,
        to,
        subject,
        text,
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending email:", error);
    }
};

mongoose.connect("mongodb+srv://harsh_kumar:harshkadatabase@firstcluster.lsjcp.mongodb.net/?retryWrites=true&w=majority&appName=Firstcluster")
    .then(() => console.log('database connected'))
    .catch((err) => console.error('ni hua', err))

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const isAlpha = /^[A-Za-z]+$/.test(password);

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'BHAI!! pura fill kro' });
    }
    if (!Number.isInteger(Number(password)) && !isAlpha){
        return res.status(400).json({ message: 'Please enter a valid value' })
    }
    try {
        const existingUser = await Usermodel.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email or username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new Usermodel({
            username,
            email,
            password: hashedPassword,
        });

        await newUser.save();

        res.status(201).json({ message: 'register ho gya hai' });
    } catch (error) {
        console.error('error registering user:', error);
        res.status(500).json({ message: 'interval server error' });
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const isAlpha = /^[A-Za-z]+$/.test(password);
    if (!username || !password ) {
        return res.status(400).json({ message: 'bhai sari entries bharo' })
    }
    personusername= username;
    if (!Number.isInteger(Number(password)) && !isAlpha){
        return res.status(400).json({ message: 'Please enter a valid password' })
    }
    const user_log = new Usermodel({
        username,
        password: hashedPassword,
    })
    

    const user = await Usermodel.findOne({ $or: [{ username }] });
    if (!user) {
        return res.status(401).json({ message: 'bhai usename ya password check kro' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'bhai usename ya password check kro' })
    }

    const token = generatetoken(user);

    // res.json({ message: 'swagatam bhai', token, personusername });
    res.json(personusername);
})

app.get("/protected", async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ message: 'samae khatam bhai' });
    }

    JWT.verify(token, jwt_secret, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "samae khatam bhai " })
        }

        res.json({ message: 'data aa gya ', user: decoded });
    })
})

app.post("/login/password-recovery", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "bhai valid id fill kro.. " })
    }

    const user = await Usermodel.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "bhai account ni mila sign up krlo... " })
    }

    const resettoken = crypto.randomBytes(20).toString('hex');
    const resettokenExpiration = Date.now() + 3600000;

    user.resetpassordtoken = resettoken;
    user.resetpasswordexpiring = resettokenExpiration;
    await user.save()

    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: process.env.MAIL_PORT,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env, MAIL_PASS,
        }
    })

    const reseturl = `http://localhost:${PORT}/reset-password/${resettoken}`;

    const mailOptions = {
        from: process.ene.MAIL_USER,
        to: user.email,
        subject: ' Password-Recovery',
        text: `You requested a password reset. Please click the following link to reset your password: ${reseturl}`
    }

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            return res.status(500).send('bhai mail ni gya!!');
        }
        res.status(200).send('Password reset email sent');
    });
});

app.post("/login/reset-password/:token", async (req, res) => {
    const { token } = req.params
    const { newpassword } = req.body

    if (!newpassword) {
        return res.status(400).send('bhai new password bharo');
    }

    const user = await Usermodel.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
        return res.status(400).send('bhai samae samapt');
    }

    const hashedPassword = await bcrypt.hash(newpassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();
    res.status(200).send('Password badal gya bhai!! ');
})

function authenticatetoken(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'bhai token me dikkat hai' })
    }

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) {
            return res.status(401).json({ message: 'bhai token galat hai' })
        }
        req.user = user;
        next();
    })
}

app.delete('/delete-account', authenticatetoken, async (req, res) => {
    try {
        const userId = req.user.id

        const user = await Usermodel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'bhai user ni mila' })
        }

        await Usermodel.findByIdAndDelete(userId);

        return res.status(200).json({ message: 'bhai account deleted successfully.' })
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'bhbai server ka issue' });
    }
})

app.get('/getuser', async (req, res) => {
    // let username = req.body.username;
    if (personusername === ""){
        console.log(" empty username")
    }else{
        console.log(personusername)
    }
    try {
        console.log("wd", personusername);
        const userdata = await Usermodel.findOne( {username : username });
        res.json(userdata);
    } catch (err) {
        res.status(500).json({ error: 'no data found' })
    } 
})

app.listen(PORT, () => {
    console.log("server is running... ", PORT);
    console.log(personusername);
})  