import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API WORKING 🚀");
});

// Start server first
app.listen(port, () => {
  console.log(`✅ Server started on http://localhost:${port}`);
});

// MongoDB Connection - Optional
if (process.env.MONGO_URI) {
  mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => {
    console.log("✅ MongoDB Connected");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    console.log("⚠️ Server running without MongoDB");
  });
} else {
  console.log("⚠️ MONGO_URI not found - Server running without MongoDB");
}
