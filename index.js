import express from 'express'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'


const app = express()
app.set('view engine', 'ejs')

//middleware para recuperar el body del json
app.use(express.json())
app.use(cookieParser())

app.use(cors())

app.use((req, res, next) => {
    const token = req.cookies.access_token

    req.session = { user: null }
    try{
        const data = jwt.verify(token, SECRET_JWT_KEY) 
        req.session.user = data
    }catch{}

    next() //seguir a la siguiente ruta o middleware
})


app.get('/', (req, res) => {
    const { user } = req.session
    res.render('index', user)
    
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body 

    try{
        const user = await UserRepository.login({ username, password })
        const token =jwt.sign(
            { id: user._id, username: user.username },
            SECRET_JWT_KEY,
            {
                expiresIn: '1h'
            })

        res
        .cookie('access_token', token, {
            httpOnly: true, //la cookie solo se puede acceder en el servidor
            secure: process.env.NODE_ENV == 'production', //la cookie solo se puede acceder en https
            sameSite: 'strict', //si es estricto la cookie solo se puede acceder desde el mismo dominio
            maxAge: 1000 * 60 * 60 //la cookie tiee validez por 1 h
        })
        .send({ user, token })
    }catch(error){
        res.status(401).send(error.message)
    }
})

app.post('/register', async (req, res) => {
    //console.log("PUNTO DE ENDPOINT DE REGISTRO")
    const { username, password } = req.body 
    console.log(username, password)
    
    try{
        const id = await UserRepository.create({ username, password })
        console.log('El id es '+id)
        res.send({ id })
        
    } catch(error){
        res.status(400).send(error.message) //no es buena idea mandarle el error del repository porque estas pasando mucha info al front (muchos hackeos)
        
    }
})

app.post('/logout', (req, res) => {
    res
        .clearCookie('access_token')
        .json({ message: 'Logout successful' })
})

app.get('/protected', (req, res) => {
    const { user } = req.session
    if(!user) return res.status(403).send('Access not authorized')
    res.render('protected', user)

})

app.get('/test', (req, res) =>{
    res.send('RESPUESTA DE PRUEBA')
})



app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})