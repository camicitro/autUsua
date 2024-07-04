import DBlocal from 'db-local' //bd local, no sigue sql
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'


const { Schema } = new DBlocal({ path: './db' }) //en esta carpeta vamos a tener la bd

const User = Schema('User', {
    _id: {type: String, required: true},
    username: { type: String, required: true },
    password: { type: String, required: true }
})

export class UserRepository{
    static async create ({ username, password }){
        //1 validaciones (se podria usar zod)
        Validation.username(username)
        Validation.password(password)

        //2 asegurarse que username no existe
        const user = User.findOne({ username })
        if (user) throw new Error('username already exists')

        const id = crypto.randomUUID()
        
        //codificar la password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()

        return id
    }

    static async login({ username, password }){
        Validation.username(username)
        Validation.password(password)

        const user = User.findOne({ username })
        if(!user) throw new Error('Username does not exists')
        
        const isValid = await bcrypt.compare(password, user.password) //no desencripta, encripta el q le pasamos y lo compara con el otro
        if (!isValid) throw new Error('password is invalid')
        
        const { password: _, ...publicUser } = user //para quitar solo la contraseña
        return publicUser

    }
}

class Validation{
    static username (username){
        if(typeof username != 'string') throw new Error('username must be a string')
        if(username.length < 3) throw new Error('username must be at least 3 characters long')
        
    }

    static password (password){
        if(typeof password != 'string') throw new Error('password must be a string')
        if(password.length < 6) throw new Error('password must be at least 6 characters long')
    
    }
}
