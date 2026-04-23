require("dotenv").config()

const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")

const app = express()

app.use(cors())
app.use(express.json())
app.use(express.static("public"))

/* FORCE INDEX LOAD */
app.get("/", (req,res)=>{
  res.sendFile(__dirname + "/public/index.html")
})

/* DB */
mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("DB Connected"))

/* MODEL */
const User = mongoose.model("User", new mongoose.Schema({
  email:String,
  password:String,
  role:{type:String, default:"user"}
}))

const Video = mongoose.model("Video", new mongoose.Schema({
  title:String,
  thumbnail:String
}))

/* AUTO ADMIN */
async function createAdmin(){
  const email = process.env.ADMIN_EMAIL
  const password = process.env.ADMIN_PASSWORD

  let exist = await User.findOne({email})
  if(!exist){
    const hash = await bcrypt.hash(password,10)
    await User.create({
      email,
      password:hash,
      role:"admin"
    })
    console.log("ADMIN SIAP")
  }
}
createAdmin()

/* AUTH */
app.post("/register", async (req,res)=>{
  const {email,password} = req.body

  if(await User.findOne({email}))
    return res.json({msg:"Email sudah ada"})

  const hash = await bcrypt.hash(password,10)

  const user = await User.create({email,password:hash})

  const token = jwt.sign({id:user._id,role:user.role}, "secret")
  res.json({token})
})

app.post("/login", async (req,res)=>{
  const {email,password} = req.body

  const user = await User.findOne({email})
  if(!user) return res.json({msg:"User tidak ada"})

  const match = await bcrypt.compare(password,user.password)
  if(!match) return res.json({msg:"Password salah"})

  const token = jwt.sign({id:user._id,role:user.role}, "secret")
  res.json({token})
})

/* AUTH MIDDLE */
function auth(req,res,next){
  try{
    req.user = jwt.verify(req.headers.authorization, "secret")
    next()
  }catch{
    res.status(401).json({msg:"Unauthorized"})
  }
}

/* ADMIN */
app.get("/admin", auth, (req,res)=>{
  if(req.user.role !== "admin") return res.json({msg:"Admin only"})
  res.json({msg:"Welcome admin"})
})

app.post("/video", auth, async (req,res)=>{
  if(req.user.role !== "admin") return res.json({msg:"Admin only"})
  res.json(await Video.create(req.body))
})

app.get("/videos", async (req,res)=>{
  res.json(await Video.find())
})

/* START */
app.listen(process.env.PORT || 3000, ()=>{
  console.log("RUNNING 🚀")
})
