const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
require('dotenv').config()
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
const app = express();

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'))
const verifyJWT = (req, res, next) =>{
    const authorization = req.headers.authorization;
    if(!authorization){
        return res.status(401).send({error: true, message: 'Unauthorized Access'})
    }
    const token = authorization.split(' ')[1];

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded)=>{
        if(err){
            return res.status(401).send({error: true, message: 'Unauthorized Access'})
        }
        req.decoded= decoded;
        next();
    })
}


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.pvq6u78.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();


    const instructorCollection = client.db("creativityDb").collection("instructors");
    const classCollection = client.db("creativityDb").collection("classes");
    const SelectClassCollection = client.db("creativityDb").collection("selectClass");
    const usersCollection = client.db("creativityDb").collection("users");
    const paymentCollection = client.db("creativityDb").collection("payments");

    app.post('/jwt', (req, res)=>{
        const user = req.body;
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h'})
        res.send({ token })
    })

    const verifyAdmin = async(req, res, next) =>{
        const email = req.decoded.email;
        const query = {email: email}
        const user = await usersCollection.findOne(query);
        if(user?.role !== 'admin'){
            return res.status(403).send({error: true, message: 'Forbidden'});
        }
        next();
    }

    const verifyInstructor = async(req, res, next) =>{
        const email = req.decoded.email;
        const query = {email: email}
        const user = await usersCollection.findOne(query);
        if(user?.role !== 'instructor'){
            return res.status(403).send({error: true, message: 'Forbidden'});
        }
        next();
    }

    //instructor apis
    app.get('/instructors', async(req, res) =>{
        const result = await instructorCollection.find().toArray();
        res.send(result);
    })

    //classes related apis
    app.get('/classes', async(req, res) =>{
        const result = await classCollection.find().toArray();
        res.send(result);
    })

    

    app.post('/classes', verifyJWT, verifyInstructor, async(req, res)=>{
        const newClass = req.body;
        const result = await classCollection.insertOne(newClass)
        res.send(result);
    })

    app.get('/my-classes/:email', verifyInstructor, async(req, res) => {
       const email = req.params.email
        //console.log(req.params.email);
        const query = {email: email}
        const result = await classCollection.find(query).toArray();
        console.log(result);
        res.send(result);
      })

    app.delete('/classes/:id', verifyJWT, verifyAdmin, async(req, res)=>{
        const id = req.params.id;
        const query = {_id: new ObjectId(id)}
        const result = await classCollection.deleteOne(query);
        res.send(result);
    })

    //user related apis
    app.get('/users', verifyJWT, verifyAdmin, async(req, res) =>{
        const result = await usersCollection.find().toArray();
        res.send(result);
    })

    app.post('/users', async(req, res)=>{
        const user = req.body;
        const query = {email: user.email}
        const existingUser = await usersCollection.findOne(query);
        if(existingUser){
            return res.send({message: 'user already exists'})
        }
        const result = await usersCollection.insertOne(user);
        res.send(result);
    })
    //security layer: verify JWT, email same, check admin
    app.get('/users/admin/:email', verifyJWT, async(req, res) =>{
        const email = req.params.email;
        if(req.decoded.email !== email){
            res.send({admin: false})
        }
        const query = {email: email}
        const user = await usersCollection.findOne(query);
        const result = {admin: user?.role === 'admin'}
        res.send(result);
    })

    app.patch('/users/admin/:id', async(req, res)=>{
        const id = req.params.id;
        const query = {_id: new ObjectId(id)}
        const updateDoc = {
            $set: {
                role: 'admin'
            },
        };
        const result = await usersCollection.updateOne(query, updateDoc);
        res.send(result);
    })

    app.get('/users/instructor/:email', verifyJWT, async(req, res) =>{
        const email = req.params.email;
        if(req.decoded.email !== email){
            res.send({instructor: false})
        }
        const query = {email: email}
        const user = await usersCollection.findOne(query);
        const result = {instructor: user?.role === 'instructor'}
        res.send(result);
    })

    app.patch('/users/instructor/:id', async(req, res)=>{
        const id = req.params.id;
        const query = {_id: new ObjectId(id)}
        const updateDoc = {
            $set: {
                role: 'instructor'
            },
        };
        const result = await usersCollection.updateOne(query, updateDoc);
        res.send(result);
    })

    //Select Class Collection
    app.get('/selected-class', verifyJWT, async(req, res) =>{
        const email = req.query.email;
        if(!email){
            res.send([]);
        }

        const decodedEmail = req.decoded.email;
        if(email !== decodedEmail){
            return res.status(403).send({error: true, message: 'Forbidden Access'})
        }

        const query = {email: email}
        const result = await SelectClassCollection.find(query).toArray();
        res.send(result);
    })
    app.post('/selected-class', async(req, res) =>{
        const item =req.body;
        const result = await SelectClassCollection.insertOne(item);
        res.send(result);
    })

    app.delete('/selected-class/:id', async(req, res) =>{
        const id = req.params.id;
        const query = { _id: new ObjectId(id)};
        const result = await SelectClassCollection.deleteOne(query);
        res.send(result);
    })

    //create payment intent
    app.post('/create-payment-intent', verifyJWT, async(req, res) =>{
        const {price} = req.body;
        const amount = price*100;
        //console.log(price, amount)
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'inr',
            payment_method_types: ['card']
        })
        console.log(paymentIntent)
        res.send({
            clientSecret: paymentIntent.client_secret
        })
    })

    //payment related api
    app.get('/payments/:email', async(req, res) =>{
        const email = req.params.email;
        const query = {email: email}
        const result = await paymentCollection.find(query).sort({date: -1}).toArray();
        res.send(result);
    })
    app.post('/payments', async(req,res) =>{
        const payment = req.body;
        const insertResult = await paymentCollection.insertOne(payment)

        const query ={_id: {$in: payment.items.map(id => new ObjectId(id))}}    
        const deleteResult = await SelectClassCollection.deleteMany(query);
        const updateResult = await SelectClassCollection.updateMany(query, { $inc: { available_seats: -1 } });
        res.send({insertResult, deleteResult, updateResult});
    })


    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Creativity center is running')
  })
  
  app.listen(port, () => {
    console.log(`Creativity center Server is running on port ${port}`)
  })