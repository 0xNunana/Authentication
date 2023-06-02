import express from 'express'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'
import * as url from 'url';
import bcrypt from 'bcryptjs';
import * as jwtJsDecode from 'jwt-js-decode';
import base64url from "base64url";
import SimpleWebAuthnServer from '@simplewebauthn/server';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const app = express()
app.use(express.json())

const adapter = new JSONFile(__dirname + '/auth.json');
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] }

const rpID = "localhost";
const protocol = "http";
const port = 8080;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

//protection from rewriting in db
function findUser(email){
  const results= db?.data?.users?.filter(u=>u.email === email);
  if(results.length === 0) return null;
  return results[0];
}

// ADD HERE THE REST OF THE ENDPOINTS
app.post("/auth/login",(req,res)=>{

const user= findUser(req.body.email)
if (user){
if (bcrypt.compareSync(req.body.password,user.password)){
  res.send({ok:true, name:user.name,email:user.email})
}else{
  res.send({ok:false,message:"Credentials not found"})
}
}else {
  res.send({ok:false, message:"Credentials not found"})
}

})




app.post("/auth/register",(req,res)=>{

const salt = bcrypt.genSaltSync(10)
const hashedPass = bcrypt.hashSync(req.body.password,salt)

  const user ={
    name:req.body.name,
    email:req.body.email,
password: hashedPass
  }
  const userFound = findUser(req.body.email)
  if (userFound){
    // already exists
    res.send({ok:false, message:"user already exists"})

  }else{
    //new user
    db.data.users.push(user);
    db.write()
    res.send({ok:true})
  }
 
 
})


app.get("*", (req, res) => {
    res.sendFile(__dirname + "public/index.html"); 
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
});

