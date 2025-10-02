const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const session = require('express-session');
const http = require('http');
const { Server } = require("socket.io");

// ======================= INITIALIZATION =======================
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password123';
const JWT_SECRET = process.env.JWT_SECRET || 'a_very_secret_key';

const teamReadyStates = {};
const missionCompleteStates = {};

// ======================= MIDDLEWARE & DATABASE =======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'admin_session_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

// UPDATED: Connection logic for MongoDB Atlas
const mongoURI = process.env.MONGO_URI || "mongodb+srv://parthagr_db_user:agrawal.db%40123@digitalsurvivor2025.vveprg8.mongodb.net/?retryWrites=true&w=majority&appName=Digitalsurvivor2025";

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ Successfully connected to MongoDB Atlas!"))
  .catch(err => console.error("❌ MongoDB Atlas connection error:", err));

const User = require('./models/user');
const Visit = require('./models/visit');

// ======================= AUTH MIDDLEWARE =======================
const checkAuthStatus = (req, res, next) => {
    try {
        const token = req.cookies.token;
        res.locals.isLoggedIn = !!(token && jwt.verify(token, JWT_SECRET));
    } catch (error) {
        res.locals.isLoggedIn = false;
    }
    next();
};

const protectPlayerRoute = (req, res, next) => {
    try {
        req.user = jwt.verify(req.cookies.token, JWT_SECRET);
        next();
    } catch (error) {
        res.redirect('/login');
    }
};

const protectAdminRoute = (req, res, next) => {
    if (req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin');
    }
};

// ======================= API ROUTES =======================
app.post('/api/register', async (req, res) => {
    try {
        const { teamId, delegateId, role, password } = req.body;
        if (!teamId || !delegateId || !role || !password) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        let team = await User.findOne({ teamId });

        if (team) {
            const isMatch = await bcrypt.compare(password, team.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Incorrect password for this team.' });
            }
            if (team.delegates.length >= 3) {
                return res.status(400).json({ message: 'This team already has 3 members.' });
            }
            if (team.delegates.some(d => d.delegateId === delegateId)) {
                return res.status(400).json({ message: 'This Delegate ID is already registered to this team.' });
            }
            if (team.delegates.some(d => d.role === role)) {
                return res.status(400).json({ message: 'This Role is already taken by a teammate.' });
            }
            team.delegates.push({ delegateId, role });
            await team.save();
            res.status(200).json({ message: `Success! Delegate ${delegateId} has joined team ${teamId}.` });
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const newTeam = new User({
                teamId,
                password: hashedPassword,
                delegates: [{ delegateId, role }]
            });
            await newTeam.save();
            res.status(201).json({ message: `Team ${teamId} created successfully! Please log in.` });
        }
    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: `Registration failed: ${messages.join(', ')}` });
        }
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'A critical server error occurred during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { teamId, password, delegateId } = req.body;
        const user = await User.findOne({ teamId });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid Team ID or password.' });
        }
        
        const delegateInfo = user.delegates.find(d => d.delegateId === delegateId);
        if (!delegateInfo) {
            return res.status(401).json({ message: 'This Delegate ID is not registered to this team.' });
        }

        const visit = new Visit({ userId: user._id, teamId: teamId, delegateId: delegateId });
        await visit.save();
        user.visitCount = (user.visitCount || 0) + 1;
        await user.save();

        const token = jwt.sign({ 
            id: user._id, 
            teamId: teamId, 
            delegateId: delegateId,
            role: delegateInfo.role
        }, JWT_SECRET, { expiresIn: '24h' });
        
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});


app.post('/api/submit-progress', protectPlayerRoute, async (req, res) => {
    const { role, answers, timeTakenSec } = req.body;
    const { teamId, delegateId } = req.user;

    const correctAnswers = {
        'cyber': { q1: 'css{mexico}' },
        'eng': { q1: 'a', q2: 'c', q3: 'a', q4: 'b', q5: 'b', q6: 'd' },
        'opera': { q1: 'css{22717,greenko,7,golconda}' }
    };

    let score = 0;
    const correctSet = correctAnswers[role];
    if (correctSet) {
        score = Object.keys(correctSet).reduce((count, key) => {
            const userAnswer = (answers[key] || '').replace(/\s+/g, '').toLowerCase();
            const correctAnswer = (correctSet[key] || '').replace(/\s+/g, '').toLowerCase();
            return count + (userAnswer === correctAnswer ? 1 : 0);
        }, 0);
    }

    try {
        const team = await User.findOne({ teamId });
        const delegate = team.delegates.find(d => d.delegateId === delegateId);
        if (delegate) {
            delegate.points = score - (delegate.hintsUsed * 5); // Apply penalty
            delegate.timeSpent = timeTakenSec;
            await team.save();
        }

        if (!missionCompleteStates[teamId]) missionCompleteStates[teamId] = {};
        missionCompleteStates[teamId][delegateId] = true;
        io.to(teamId).emit('mission-status-update', missionCompleteStates[teamId]);
        
        const allDelegatesFinished = team.delegates.length === 3 && team.delegates.every(d => d.timeSpent > 0);
        if (allDelegatesFinished) {
            io.to(teamId).emit('team-finished-round2');
            delete missionCompleteStates[teamId];
        }
        
        res.status(200).json({ message: 'Progress saved!', score: delegate.points });
    } catch (error) {
        res.status(500).json({ message: 'Error saving progress.' });
    }
});

app.post('/api/get-hint', protectPlayerRoute, async (req, res) => {
    const { questionId } = req.body;
    const { teamId, delegateId, role } = req.user;

    const hints = {
        'cyber': { q1: 'Think about a major cybersecurity event in 2020 involving a software supply chain. The malicious domain was registered in a capital city known for its vibrant culture and history.' },
        'eng': {
            q1: 'Focus on the "OR" conditions. Phantom Operative and Manual Override can force activation on their own.',
            q2: 'The first gate is a NOR gate. The second is a NAND gate. The final gate is an AND gate.',
            q3: 'Trace the loop for each index. Even indices are doubled, odd indices are decremented.',
            q4: 'In C, dividing two integers results in an integer. The decimal part is truncated before being assigned to the float.',
            q5: 'The `sum` variable is never initialized to 0. It starts with a random garbage value.',
            q6: 'Arrays in C are 0-indexed. An array of size 5 has indices 0, 1, 2, 3, and 4. Accessing index 5 is out of bounds.'
        },
        'opera': { q1: 'The racing event is the Formula E championship. Research the title sponsor for the 2024 season in that specific city. The fort is a famous landmark in the same city.' }
    };
    const hintText = hints[role]?.[questionId];

    if (hintText) {
        try {
            const team = await User.findOne({ teamId });
            const delegate = team.delegates.find(d => d.delegateId === delegateId);
            if(delegate) {
                delegate.hintsUsed = (delegate.hintsUsed || 0) + 1;
                await team.save();
            }
            res.status(200).json({ hint: hintText });
        } catch (error) {
            res.status(500).json({ message: 'Error applying hint penalty.' });
        }
    } else {
        res.status(404).json({ message: 'Hint not found.' });
    }
});

app.post('/api/submit-final-challenge', protectPlayerRoute, async (req, res) => {
    const { finalAnswer } = req.body;
    const { teamId } = req.user;
    const FINAL_CHALLENGE_ANSWER = "METAVERSE";

    if (finalAnswer && finalAnswer.trim().toUpperCase() === FINAL_CHALLENGE_ANSWER) {
        try {
            await User.findOneAndUpdate({ teamId }, { round3EndTime: new Date() });
            res.status(200).json({ success: true, message: 'Challenge complete! Well done.' });
        } catch (error) {
            res.status(500).json({ success: false, message: 'Error saving final time.' });
        }
    } else {
        res.status(400).json({ success: false, message: 'Incorrect. Try again.' });
    }
});


// ======================= PAGE ROUTES =======================
app.get('/', checkAuthStatus, (req, res) => {
    res.render('index', { title: 'Cyber Survivor', isLoggedIn: res.locals.isLoggedIn });
});

app.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

app.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
});

app.get('/dashboard', protectPlayerRoute, (req, res) => {
    res.render('dashboard', { title: 'Dashboard', user: req.user });
});

app.get('/waiting', protectPlayerRoute, (req, res) => {
    res.render('waiting', { title: 'Waiting for Team', user: req.user });
});

app.get('/post-mission-wait', protectPlayerRoute, (req, res) => {
    res.render('post_mission_waiting', { title: 'Mission Complete - Awaiting Team', user: req.user });
});

app.get('/webex', protectPlayerRoute, (req, res) => {
    res.render('webex', { title: 'Final Challenge', user: req.user });
});

app.get('/role/cyber', protectPlayerRoute, (req, res) => {
    res.render('role_cyber', { title: 'CyberSecurity Expert', user: req.user });
});

app.get('/role/eng', protectPlayerRoute, (req, res) => {
    res.render('role_engineer', { title: 'Engineer', user: req.user });
});

app.get('/role/opera', protectPlayerRoute, (req, res) => {
    res.render('role_operations', { title: 'Operations Expert', user: req.user });
});

// ======================= ADMIN ROUTES =======================
app.get('/admin', (req, res) => {
    res.render('admin_login', { title: 'Admin Login', error: null });
});

app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && password === ADMIN_PASS) {
        req.session.isAdmin = true;
        res.redirect('/admin/dashboard');
    } else {
        res.render('admin_login', { title: 'Admin Login', error: 'Invalid username or password.' });
    }
});

app.get('/admin/dashboard', protectAdminRoute, async (req, res) => {
    try {
        const teams = await User.find({});
        res.render('admin', { title: 'Admin Dashboard', teams: teams });
    } catch (error) {
        res.status(500).send('Error fetching team data.');
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/admin/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/admin');
    });
});

// ======================= REAL-TIME LOGIC =======================
io.on('connection', (socket) => {
    let currentTeamId = null;
    let currentDelegateId = null;

    socket.on('join-team-room', ({ teamId, delegateId }) => {
        socket.join(teamId);
        currentTeamId = teamId;
        currentDelegateId = delegateId;
        console.log(`[Socket] Delegate '${delegateId}' from team '${teamId}' connected and joined room.`);
        socket.emit('team-status-update', teamReadyStates[teamId] || {});
    });

    socket.on('player-ready', async ({ teamId, delegateId }) => {
        if (!teamReadyStates[teamId]) {
            teamReadyStates[teamId] = {};
        }
        teamReadyStates[teamId][delegateId] = true;
        console.log(`[Game] Delegate '${delegateId}' from team '${teamId}' is ready.`);

        io.to(teamId).emit('team-status-update', teamReadyStates[teamId]);

        if (Object.keys(teamReadyStates[teamId]).length === 3) {
            console.log(`[Game] Team '${teamId}' is fully ready. Starting mission!`);
            await User.findOneAndUpdate({ teamId }, { round2StartTime: new Date() });
            io.to(teamId).emit('start-mission');
            delete teamReadyStates[teamId];
        }
    });

    socket.on('join-post-mission-room', ({ teamId, delegateId }) => {
        socket.join(teamId);
        socket.emit('mission-status-update', missionCompleteStates[teamId] || {});
    });

    socket.on('disconnect', () => {
        if (currentTeamId && currentDelegateId && teamReadyStates[currentTeamId]) {
            delete teamReadyStates[currentTeamId][currentDelegateId];
            io.to(currentTeamId).emit('team-status-update', teamReadyStates[currentTeamId]);
            console.log(`[Game] Delegate '${currentDelegateId}' from team '${currentTeamId}' disconnected and is no longer ready.`);
        }
    });
});

// ======================= START SERVER =======================
server.listen(PORT, () => {
    console.log(`🚀 Server is running at http://localhost:${PORT}`);
});

