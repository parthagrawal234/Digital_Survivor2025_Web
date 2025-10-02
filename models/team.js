const mongoose = require('mongoose');

const teamSchema = new mongoose.Schema({
  delegateId: { type: String, unique: true, required: true },
  visits: { type: Number, default: 0 },
  cyber: { type: Number },
  cybertime: { type: Number },
  eng: { type: Number },
  engtime: { type: Number },
  opera: { type: Number },
  operatime: { type: Number }
});

module.exports = mongoose.model('Team', teamSchema);
