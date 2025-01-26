const mongoose = require("mongoose")

const MessageSchema = mongoose.Schema(
  {
    sender: { type: mongoose.Types.ObjectId, ref: "User" },
    recipient: { type: mongoose.Types.ObjectId, ref: "User" },
    text: String,
  },
  { timestamps: true }
);
const MessageModel = mongoose.model("Message", MessageSchema);
module.exports = MessageModel;
