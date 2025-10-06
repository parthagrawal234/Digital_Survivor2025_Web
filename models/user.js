const mongoose = require('mongoose');

const delegateSchema = new mongoose.Schema({
    delegateId: {
        type: String,
        required: [true, 'Delegate ID is required.']
    },
    role: {
        type: String,
        required: [true, 'A role must be selected.'],
        enum: {
            values: ['cyber', 'eng', 'opera'],
            message: '{VALUE} is not a supported role.'
        }
    },
    points: {
        type: Number,
        default: 0
    },
    timeSpent: {
        type: Number,
        default: 0
    },
    hintsUsed: {
        type: Number,
        default: 0
    },
    lastKnownLocation: {
        type: String,
        default: '/dashboard'
    }
});

const userSchema = new mongoose.Schema({
    teamId: {
        type: String,
        unique: true,
        required: [true, 'Team ID is required.']
    },
    password: {
        type: String,
        required: [true, 'Password is required.']
    },
    delegates: [delegateSchema],
    solvedQuestions: {
        type: [String],
        default: []
    },
    visitCount: {
        type: Number,
        default: 0
    },
    round2StartTime: {
        type: Date
    },
    round3EndTime: {
        type: Date
    }
});

module.exports = mongoose.model('User', userSchema);

