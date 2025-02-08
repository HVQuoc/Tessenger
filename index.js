const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const ws = require("ws");
dotenv.config();
const mongoUrl = process.env.MONGO_URL;
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);
mongoose.connect(mongoUrl);

const app = express();
app.use(
  cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
  })
);
app.use(express.json());
app.use(cookieParser());

const User = require("./models/User");
const Message = require("./models/Message");

app.get("/", (req, res) => {
  res.json("ok");
});

async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (err) throw err;
        resolve(userData);
      });
    } else {
      reject("no token");
    }
  });
}

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    const passOk = bcrypt.compareSync(password, foundUser.password);
    if (passOk) {
      jwt.sign(
        { userId: foundUser._id, username: foundUser.username },
        jwtSecret,
        {},
        (err, token) => {
          res.cookie("token", token).json({
            id: foundUser._id,
          });
        }
      );
    } else {
      res.status(401).json("Bad credentials: invalid login information");
    }
  } else {
    res.status(403).json({ message: "Incorrect username or password" });
  }
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    jwt.sign(
      { userId: createdUser._id, username },
      jwtSecret,
      {},
      (err, token) => {
        if (err) throw err;
        res.cookie("token", token).status(201).json({
          id: createdUser._id,
        });
      }
    );
  } catch (err) {
    if (err) throw err;
    res.status(500).json("error");
  }
});

app.get("/profile", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    });
  } else {
    res.status(401).json("Unauthorized: no token");
  }
});

app.get("/messages/:userId", async (req, res) => {
  const { userId } = req.params;
  const userData = await getUserDataFromRequest(req);
  const requestUserId = userData.userId;
  // console.log("user ids:", { userId, requestUserId });
  const messages = await Message.find({
    sender: { $in: [userId, requestUserId] },
    recipient: { $in: [userId, requestUserId] },
  }).sort({ createdAt: 1 });

  res.json(messages);
});

app.get("/people", async (req, res) => {
  const users = await User.find({}, { _id: 1, username: 1 });
  res.json(users);
});

const server = app.listen(4000);

// add socket server

const wss = new ws.WebSocketServer({ server });
wss.on("connection", (connection, req) => {
  // console.log("connected", req.headers)
  // connection.send('hello')

  // grab the information of the connected client
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookies = cookies
      .split(";")
      .find((str) => str.startsWith("token="));
    if (tokenCookies) {
      const token = tokenCookies.split("=")[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }

  // listening to the message event
  connection.on("message", async (message) => {
    // console.log("message event", message.toString())
    const messageData = JSON.parse(message.toString());
    const { recipient, text } = messageData.message;
    if (recipient && text) {
      // save message to database
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
      });

      // send message to recipient
      const onlineRecipient = [...wss.clients].find(
        (c) => c.userId === recipient
      );
      // [...wss.clients]
      //   .find((c) => c.userId === recipient)
      if (onlineRecipient)
        onlineRecipient.send(
          JSON.stringify({
            text,
            sender: connection.userId,
            recipient,
            _id: messageDoc._id,
          })
        );
    }
  });

  // send all active clients to all connected one
  [...wss.clients].forEach((client) => {
    client.send(
      JSON.stringify({
        online: [...wss.clients].map((c) => ({
          userId: c.userId,
          username: c.username,
        })),
      })
    );
  });
});
