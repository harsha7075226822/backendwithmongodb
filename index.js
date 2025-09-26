import express from "express";
import {z} from "zod";
import bcrypt from "bcrypt";
import mongoose, { Schema, model } from "mongoose";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import { userModel } from "./models/userModels.js";
import { AdminModel } from "./models/adminModel.js";
import { TechEventsModel } from "./models/TechEvents.js";

const app = express();
dotenv.config();

app.use(express.json());
app.use(cors({
    methods: ["GET", "POST", "PUT", "DELETE"]
}))


app.get("/", (req,res) => {
    res.status(200).json({ message: "GET is successful" });
});

// *---------------register---------------*
app.post("/signup", async (req,res) => {
    const { username, email, password } = req.body;

    const UserRules = z.object({
        username: z.string().min(4).max(15),
        email: z.email(),
        password: z.string().min(6).max(15)
    });

    const parsedData = UserRules.safeParse({ username, email, password });

    if (!parsedData.success) {
        return res.status(400).json({
            message: "Please give valid input",
            error: parsedData.error
        });
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
        return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await userModel.create({ 
        username,
        email,
        password: hashedPassword
    });

    res.status(200).json({
        message: "User created successfully",
        result: newUser
    });
});

// *---------------USER login----------------*
app.post("/signin", async (req,res) => {
    const { email, password } = req.body;

    const isUserPresent = await userModel.findOne({ email });
    if (!isUserPresent) {
        return res.status(400).json({ message: "Invalid email or user not found" });
    }

    const verification = await bcrypt.compare(password, isUserPresent.password);
    if (!verification) {
        return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
        { id: isUserPresent._id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.status(200).json({
        message: "Signin successful",
        jwt_token:token
    });
});

// *******ADMIN**********

// ------------Add new admin details---------------*
app.post("/admin/register",async(req,res)=>{
    const {email,code} = req.body;
    const AdminRules = z.object({
        email:z.email(),
        code:z.string()
    })
    
    const AdminData = AdminRules.safeParse({email,code})
    if(!AdminData.success) {
        return res.status(400).json({
            message:"Give Valid Inputs"
        })
    }

    const existingAdmin = await AdminModel.findOne({email})
    if(existingAdmin) {
        return res.status(400).json({
            message:"Email already exists"
        })
    }
    const hashedAdminCode = await bcrypt.hash(code,10);
    const newAdmin = await AdminModel.create({
        email,
        code:hashedAdminCode
    })
    res.status(200).json({
        message:"New Admin Created"
    })
})


// *-------------ADMIN LOGIN--------------*
app.post("/admin/login",async(req,res)=>{
    const {email,code} = req.body;
    if (!email || !code) {
        return res.status(400).json({
            message:"Email and code are required"
        })
    }
    const isAdminPresent = await AdminModel.findOne({email})
    if (!isAdminPresent) {
        return res.status(400).json({
            message:"Invalid Email"
        })
    }
    const AdminVerify = await bcrypt.compare(code,isAdminPresent.code);
    if(!AdminVerify) {
        return res.status(400).json({
            message:"Invalid CODE"
        })
    }
    const AdminToken = jwt.sign(
        {id:isAdminPresent._id},
        process.env.ADMIN_CODE,
        {expiresIn:"1h"}
    )
    res.status(200).json({
        message:"Login Successfull",
        adminToken:AdminToken
    })

})

// *******create event***********
app.post("/events/post",async(req,res)=>{
    try {
        const {EventTitle,EventType,Organizer,OnlineorOffline,PricePool,OrganisationName,City,State,Venue,StartDate,EndDate,SpecifiedStacks} = req.body;
        const newEvent = new TechEventsModel({EventTitle,EventType,Organizer,OnlineorOffline,PricePool,OrganisationName,City,State,Venue,StartDate,EndDate,SpecifiedStacks})
        await newEvent.save();
        res.status(200).json({
            message:"Event Created Successfully",
            EventDetails:newEvent
        })
    }
    catch(err) {
        console.log(`Error:${err}`)
    }
})

app.get("/events",async(req,res)=>{
    try {
        const events = await TechEventsModel.find();
        if(!events) {
            res.status(400).json({
                message:"No events are there"
            })
        }
        res.status(200).json({
            message:"Getting all events",
            allevents:events
        })
    }
    catch(err) {
        console.log(`Error:${err}`)
    }

})

app.get("/events/:id",async(req,res)=> {
    try{
        const id = req.params.id
        const specificEvent = await TechEventsModel.findById(id);
        if(!specificEvent) {
            res.status(400).json({
                message:"Todo not found"
            })
        }
        res.status(200).json(specificEvent)
    }
    catch(err) {
        console.log(`Error:${err}`)
    }
})

app.put("/events/:id",async(req,res)=> {
    try {
        const id = req.params.id
        const {EventTitle,EventType,Organizer,OnlineorOffline,PricePool,OrganisationName,City,State,Venue,StartDate,EndDate,SpecifiedStacks} = req.body;
        const updatedEvent = await TechEventsModel.findByIdAndUpdate(id,{EventTitle,EventType,Organizer,OnlineorOffline,PricePool,OrganisationName,City,State,Venue,StartDate,EndDate,SpecifiedStacks})
        if(!updatedEvent) return res.status(404).json("Error")
        res.status(200).json({
            message:updatedEvent
        })

    }
    catch(err) {
        console.log(`Error:${err}`)
    }
})

app.delete("/events/:id",async(req,res)=>{
    try{
        const DeleteEvent = await TechEventsModel.findByIdAndDelete(req.params.id);
        if (!DeleteEvent) return res.status(404).json({ error: "Event not found" });
        res.json({ message: "Event deleted successfully" });
    }
    catch(err) {
        console.log(`Error:${err}`)
    }
})

async function connection() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("MongoDB connected");
        app.listen(5678, () => {
            console.log("Server is running at port 5678");
        });
    } catch (err) {
        console.error("Error connecting to MongoDB:", err);
        process.exit(1);
    }
}
connection();
