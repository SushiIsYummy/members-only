const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const messageSchema = new Schema({
  title: { type: String, ref: 'Author', required: true },
  timestamp: { type: String, required: true },
  text: { type: String, required: true },
  user: { type: Schema.Types.ObjectId, ref: 'User' },
});

module.exports = mongoose.model('Message', messageSchema);
