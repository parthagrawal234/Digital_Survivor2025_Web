const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const session = require('express-session');
const http = require('http');
const { Server } = require("socket.io");
const MongoStore = require('connect-mongo');

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

const mongoURI = process.env.MONGO_URI || "mongodb+srv://parthagr_db_user:agrawal.db%40123@digitalsurvivor2025.vveprg8.mongodb.net/cyber_survivor?retryWrites=true&w=majority&appName=Digitalsurvivor2025";

app.use(session({
    secret: process.env.SESSION_SECRET || 'admin_session_secret_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoURI, collectionName: 'sessions' }),
    cookie: { maxAge: 60 * 60 * 1000 }
}));

mongoose.connect(mongoURI, {})
  .then(() => console.log("✅ Successfully connected to MongoDB Atlas!"))
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

const redirectIfLoggedIn = (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        try {
            jwt.verify(token, JWT_SECRET);
            return res.redirect('/dashboard');
        } catch (error) { next(); }
    } else { next(); }
};

const authorizeRole = (requiredRole) => {
    return (req, res, next) => {
        if (req.user && req.user.role === requiredRole) {
            next();
        } else {
            res.status(403).redirect('/dashboard');
        }
    };
};

const trackLocation = (req, res, next) => {
    if (req.user && req.user.teamId && req.user.delegateId) {
        User.updateOne(
            { teamId: req.user.teamId, "delegates.delegateId": req.user.delegateId },
            { $set: { "delegates.$.lastKnownLocation": req.originalUrl } }
        ).catch(err => console.error(`Failed to update location: ${err.message}`));
    }
    next();
};

// ======================= API ROUTES =======================
app.post('/api/register', async (req, res) => {
    try {
        const { teamId, delegateId, role, password } = req.body;
        if (!teamId || !delegateId || !role || !password) return res.status(400).json({ message: 'All fields are required.' });
        let team = await User.findOne({ teamId });
        if (team) {
            const isMatch = await bcrypt.compare(password, team.password);
            if (!isMatch) return res.status(401).json({ message: 'Incorrect password for this team.' });
            if (team.delegates.length >= 3) return res.status(400).json({ message: 'This team already has 3 members.' });
            if (team.delegates.some(d => d.delegateId === delegateId)) return res.status(400).json({ message: 'This Delegate ID is already registered.' });
            if (team.delegates.some(d => d.role === role)) return res.status(400).json({ message: 'This Role is already taken.' });
            team.delegates.push({ delegateId, role });
            await team.save();
            res.status(200).json({ message: `Success! Delegate ${delegateId} has joined team ${teamId}.` });
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const newTeam = new User({ teamId, password: hashedPassword, delegates: [{ delegateId, role }] });
            await newTeam.save();
            res.status(201).json({ message: `Team ${teamId} created successfully! Please log in.` });
        }
    } catch (error) {
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ message: `Registration failed: ${messages.join(', ')}` });
        }
        res.status(500).json({ message: 'A critical server error occurred.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { teamId, password, delegateId } = req.body;
        const user = await User.findOne({ teamId });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Invalid Team ID or password.' });
        const delegateInfo = user.delegates.find(d => d.delegateId === delegateId);
        if (!delegateInfo) return res.status(401).json({ message: 'This Delegate ID is not registered to this team.' });
        const visit = new Visit({ userId: user._id, teamId: teamId, delegateId: delegateId });
        await visit.save();
        user.visitCount = (user.visitCount || 0) + 1;
        await user.save();
        const token = jwt.sign({ id: user._id, teamId: teamId, delegateId: delegateId, role: delegateInfo.role }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/logout', protectPlayerRoute, async (req, res) => {
    try {
        const { teamId, delegateId } = req.user;
        await User.updateOne(
            { teamId: teamId, "delegates.delegateId": delegateId },
            { $set: { "delegates.$.lastKnownLocation": "/dashboard" } }
        );
    } catch (error) {
        console.error("Logout location reset error:", error);
    }
    res.clearCookie('token');
    res.redirect('/');
});

app.post('/api/submit-progress', protectPlayerRoute, async (req, res) => {
    const { role, answers, timeTakenSec } = req.body;
    const { teamId, delegateId } = req.user;
    const correctAnswers = { 'cyber': { q1: 'css{mexico}' }, 'eng': { q1: 'a', q2: 'c', q3: 'a', q4: 'b', q5: 'b', q6: 'd' }, 'opera': { q1: 'css{22717,greenko,7,golconda}' } };
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
            delegate.points = score - (delegate.hintsUsed * 5);
            delegate.timeSpent = timeTakenSec;
            await team.save();
        }
        if (!missionCompleteStates[teamId]) missionCompleteStates[teamId] = {};
        missionCompleteStates[teamId][delegateId] = true;
        io.to(teamId).emit('mission-status-update', missionCompleteStates[teamId]);
        res.status(200).json({ message: 'Progress saved!', score: delegate.points });
    } catch (error) {
        res.status(500).json({ message: 'Error saving progress.' });
    }
});

app.post('/api/get-hint', protectPlayerRoute, async (req, res) => {
    const { questionId } = req.body;
    const { teamId, delegateId, role } = req.user;
    const hints = { /* ... all hint text ... */ };
    const hintText = hints[role]?.[questionId];
    if (hintText) {
        try {
            const team = await User.findOne({ teamId });
            const delegate = team.delegates.find(d => d.delegateId === delegateId);
            if (delegate) {
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
app.get('/', checkAuthStatus, (req, res) => res.render('index', { title: 'Cyber Survivor', isLoggedIn: res.locals.isLoggedIn }));
app.get('/login', redirectIfLoggedIn, (req, res) => res.render('login', { title: 'Login' }));
app.get('/register', redirectIfLoggedIn, (req, res) => res.render('register', { title: 'Register' }));
app.get('/dashboard', protectPlayerRoute, async (req, res) => {
    try {
        const team = await User.findOne({ teamId: req.user.teamId });
        const delegate = team ? team.delegates.find(d => d.delegateId === req.user.delegateId) : null;
        if (delegate && delegate.lastKnownLocation && delegate.lastKnownLocation !== '/dashboard') {
            return res.redirect(delegate.lastKnownLocation);
        }
        if (delegate) {
            delegate.lastKnownLocation = '/dashboard';
            await team.save();
        }
        res.render('dashboard', { title: 'Dashboard', user: req.user });
    } catch (error) {
        res.render('dashboard', { title: 'Dashboard', user: req.user });
    }
});
app.get('/waiting', protectPlayerRoute, trackLocation, async (req, res) => {
    try {
        const team = await User.findOne({ teamId: req.user.teamId });
        res.render('waiting', { 
            title: 'Waiting for Team', 
            user: { 
                ...req.user,
                team: team // Add the team information to the user object
            } 
        });
    } catch (error) {
        console.error('Error fetching team data:', error);
        res.render('waiting', { title: 'Waiting for Team', user: req.user });
    }
});
app.get('/post-mission-wait', protectPlayerRoute, trackLocation, (req, res) => res.render('post_mission_waiting', { title: 'Mission Complete - Awaiting Team', user: req.user }));
app.get('/webex', protectPlayerRoute, trackLocation, (req, res) => res.render('webex', { title: 'Final Challenge', user: req.user }));
app.get('/role/cyber', protectPlayerRoute, authorizeRole('cyber'), trackLocation, (req, res) => res.render('role_cyber', { title: 'CyberSecurity Expert', user: req.user }));
app.get('/role/eng', protectPlayerRoute, authorizeRole('eng'), trackLocation, (req, res) => res.render('role_engineer', { title: 'Engineer', user: req.user }));
app.get('/role/opera', protectPlayerRoute, authorizeRole('opera'), trackLocation, (req, res) => res.render('role_operations', { title: 'Operations Expert', user: req.user }));

// ======================= ADMIN ROUTES =======================
app.get('/admin', (req, res) => res.render('admin_login', { title: 'Admin Login', error: null }));
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
        if (err) return res.redirect('/admin/dashboard');
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
        // Emit current state to the newly joined player
        socket.emit('team-status-update', teamReadyStates[teamId] || {});
        // Also emit to all team members to ensure everyone is in sync
        io.to(teamId).emit('team-status-update', teamReadyStates[teamId] || {});
    });
    socket.on('player-ready', async ({ teamId, delegateId }) => {
        console.log(`Player Ready - Team: ${teamId}, Delegate: ${delegateId}`);
        
        if (!teamReadyStates[teamId]) {
            teamReadyStates[teamId] = {};
        }
        teamReadyStates[teamId][delegateId] = true;
        
        // Emit to all team members including sender
        io.to(teamId).emit('team-status-update', teamReadyStates[teamId]);
        
        // Check if all three players are ready
        const team = await User.findOne({ teamId });
        if (team) {
            console.log(`Team ${teamId} has ${team.delegates.length} delegates`);
            console.log(`Ready players: ${Object.keys(teamReadyStates[teamId]).length}`);
            
            if (team.delegates.length === Object.keys(teamReadyStates[teamId]).length) {
                console.log(`All players ready for team ${teamId}, starting mission`);
                io.to(teamId).emit('start-mission');
                delete teamReadyStates[teamId];
            }
        } else {
            console.error(`Team ${teamId} not found in database`);
            socket.emit('error', { message: 'Team not found' });
        }
    });
    socket.on('join-post-mission-room', async ({ teamId, delegateId }) => {
        socket.join(teamId);
        const team = await User.findOne({ teamId });
        if (!team) return;
        const completedDelegates = team.delegates.filter(d => d.timeSpent > 0).map(d => d.delegateId);
        const statusObject = {};
        completedDelegates.forEach(id => statusObject[id] = true);
        io.to(teamId).emit('mission-status-update', statusObject);
        if (completedDelegates.length === 3) {
            io.to(teamId).emit('team-finished-round2');
        }
    });
    socket.on('disconnect', () => {
        if (currentTeamId && currentDelegateId && teamReadyStates[currentTeamId]) {
            delete teamReadyStates[currentTeamId][currentDelegateId];
            io.to(currentTeamId).emit('team-status-update', teamReadyStates[currentTeamId]);
        }
    });
});

// ======================= START SERVER =======================
server.listen(PORT, () => {
    console.log(`🚀 Server is running at http://localhost:${PORT}`);
});

