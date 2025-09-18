import express from "express";
import z from "zod";
import bcrypt from "bcrypt";
import { userModel } from "./db.js";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import {cors} from "cors"

const app = express();
dotenv.config();

app.use(express.json());
app.use(cors({
    method: ["GET", "POST", "PUT", "DELETE"]
}))

app.get("/", (req,res) => {
    res.status(200).json({ message: "GET is successful" });
});


app.post("/signup", async (req,res) => {
    const { username, email, password } = req.body;

    const UserRules = z.object({
        username: z.string().min(4).max(15),
        email: z.email(),
        password: z.string().min(6).max(15)
    });

    const parsedData = UserRules.safeParse({ username, email, password });

    if (!parsedData.success) {
        return res.status(401).json({
            message: "Please give valid input",
            error: parsedData.error
        });
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
        return res.status(401).json({ message: "Email already exists" });
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


app.post("/signin", async (req,res) => {
    const { email, password } = req.body;

    const isUserPresent = await userModel.findOne({ email });
    if (!isUserPresent) {
        return res.status(401).json({ message: "Invalid email or user not found" });
    }

    const verification = await bcrypt.compare(password, isUserPresent.password);
    if (!verification) {
        return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
        { id: isUserPresent._id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.status(200).json({
        message: "Signin successful",
        token
    });
});


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
