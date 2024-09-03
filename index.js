const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");
const saltRounds = 10;

// middleware
app.use(cors());
app.use(express.json());

// send email
const sendEmail = (emailAddress, emailData) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.TRANSPORTER_EMAIL,
      pass: process.env.TRANSPORTER_PASS,
    },
  });
  // verify connection
  transporter.verify(function (error, success) {
    if (error) {
      console.log(error);
    } else {
      console.log("Server is ready to take our messages");
    }
  });
  const mailBody = {
    from: `"HealthChamber" <${process.env.TRANSPORTER_EMAIL}>`,
    to: emailAddress,
    subject: emailData.subject,
    html: emailData.message,
  };

  transporter.sendMail(mailBody, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("Email Sent: " + info.response);
    }
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.43teffq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // await client.connect();
    const userCollection = client.db("Health-Chamber").collection("users");
    const doctorCollection = client.db("Health-Chamber").collection("doctors");
    const patientsCollection = client
      .db("Health-Chamber")
      .collection("patients");

    // jwt related works
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // middlewares/verifyToken
    const verifyToken = (req, res, next) => {
      console.log("inside verifytoken", req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "Unauthorized Access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(400).send({ message: "Invalid token" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // check if user is admin or not
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden Admin Access" });
      }
      next();
    };

    // user related APIs
    // get all users
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      console.log(req.headers);
      const result = await userCollection.find().toArray();
      res.send(result);
    });
    // get specific user
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const result = await userCollection.findOne({ email });
      res.send(result);
    });
    // post a new user
    app.put("/users", async (req, res) => {
      const user = req.body;
      const query = { email: user?.email };
      const isExist = await userCollection.findOne(query);
      if (isExist) {
        res.send(isExist);
      } else {
        bcrypt.genSalt(saltRounds, function (err, salt) {
          bcrypt.hash(user?.password, salt, async function (err, hash) {
            const userInfo = {
              name: user?.name,
              email: user?.email,
              password: hash,
              role: "user",
            };
            // save user for the first time
            const options = { upsert: true };
            const updateDoc = {
              $set: {
                ...userInfo,
                timestamp: Date.now(),
              },
            };
            const result = await userCollection.updateOne(
              query,
              updateDoc,
              options
            );
            // welcome message to email
            sendEmail(user?.email, {
              subject: "Welcome to PicoTask Rush website!",
              message: `Hope you will find a lot of resources which you find`,
            });
            res.send(result);
          });
        });
      }
    });

    // get all doctors
    app.get("/doctors", async (req, res) => {
      // console.log("pagination query", req.query);
      const pages = parseInt(req.query.pages);
      const size = parseInt(req.query.size);
      const result = await doctorCollection
        .find()
        .skip(pages * size)
        .limit(size)
        .toArray();
      res.send(result);
    });

    // post new patient
    app.put("/patients", async (req, res) => {
      const patient = req.body;
      const result = await patientsCollection.insertOne(patient);
      res.send(result);
    });

    // get all patients
    app.get("/patients", verifyToken, verifyAdmin, async (req, res) => {
      console.log(req.headers);
      const result = await patientsCollection.find().toArray();
      res.send(result);
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", async (req, res) => {
  res.send("Health Chamber server is Running");
});

app.listen(port, async (req, res) => {
  console.log(`Health Chamber Running on PORT : ${port}`);
});
