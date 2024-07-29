const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");
const saltRounds = 10;

// middleware
app.use(cors());
app.use(express.json());

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

    // user related APIs
    // get all users
    app.get("/users", verifyToken, async (req, res) => {
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
      }

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
          res.send(result);
        });
      });
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
