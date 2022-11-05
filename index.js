const express = require('express')
const mongoose = require('mongoose')
const bycrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {expressjwt: expressJwt} = require('express-jwt')
const User = require('./user')
mongoose.connect('mongodb+srv://Javier12181998:Lolowasd65.@cluster0.51bil2f.mongodb.net/auth?retryWrites=true&w=majority');
const app = express();
app.use(express.json())
console.log()
const validateJwt = expressJwt({secret: process.env.SECRET, algorithms: ['HS256']})
const signToken = _id => jwt.sign({_id}, process.env.SECRET)
app.post('/register', async (req, res) =>{
    const {body} = req
    console.log({body})
    try {
        const isUser = await User .findOne({email: body.email})
        if(isUser){
            return res.status(403).send('usuario ya existe')
        }
        const salt = await bycrypt.genSalt()
        const hashed = await bycrypt.hash(body.password, salt)
        const user = await User.create({email: body.email, password: hashed, salt})
        const signed = signToken(user._id)
        res.status(500).send(signed)
    } catch (error) {
        console.log(error)
        res.status(500).send(error.message)
    }
})
app.post('/login', async (req, res) =>{
    const { body } = req
    try {
        const user = await User.findOne({email: body.email})
        if (!user) {
            res.status(403).send('usuario y/o contraseña invalida')
        } else {
            const isMatch = await bycrypt.compare(body.password, user.password)
            if (isMatch) {
                const signed = signToken(user._id)
                res.status(200).send(signed)
            } else {
                res.status(403).send('usuario y/o contraseña invalida')                
            }
        }
    } catch (error) {
        res.status(500).send(error.message)
    }
})
const findAndAsignUser = async (req, res, next) =>{
    try {
        const user = await User.findById(req.auth._id)
        if (!user) {
            return res.status(401).end();
        }
        req.user = user
        next()
    } catch (error) {
       next(error); 
    }
}
const isAuthenticated = express.Router().use(validateJwt, findAndAsignUser)
app.get('/lele', isAuthenticated, (req, res)=>{
    throw new Error('nuevo error')
})
app.use((error, req, res, next) =>{
    console.error('Mi nuevo error', error.stack)
    next(error)
})
app.use((error, req, res, next) =>{
    res.send('ha ocurrido un error')
})
app.listen(3000, () =>{
    console.log('listening in port 3000')
})