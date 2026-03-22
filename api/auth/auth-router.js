const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require('./auth-middleware');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // bu secret'ı kullanın!
const { ekle, goreBul } = require("../users/users-model");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  const newUser = req.body;
  const hash = bcrypt.hashSync(newUser.password, BCRYPT_ROUNDS);
  newUser.password = hash;
try {
  const addedUser = await ekle(newUser);
  return res.status(201).json(addedUser);
} catch (error) {
  res.json(error)
}

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", usernameVarmi, async (req, res) => {
  try {
    const { password } = req.body;

    const user = req.user;

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Geçersiz kriter" });
    }

    const token = generateToken(user);

    return res.status(200).json({
      message: `${user.username} geri geldi!`,
      token
    });

  } catch (error) {
    return res.status(500).json(error);
  }
});
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */


const generateToken = (user)=> {
const payload = {
   "role_name": user.role_name,
  "subject": user.user_id,
  "username": user.username
 
};
const options = {
  expiresIn: "1d"
};
const token = jwt.sign(payload, JWT_SECRET, options);
return token;
}


module.exports = router;
