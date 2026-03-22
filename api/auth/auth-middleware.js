const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const jwt = require("jsonwebtoken");
const { goreBul } = require("../users/users-model");
const sinirli = (req, res, next) => {
  if(!req.headers.authorization){
   return res.status(401).json({message: "Token gereklidir"})
  }
    const token= req.headers.authorization.split(" ").pop();
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch (error) {
     return res.status(401).json({message: "Token gecersizdir"})
    }
  
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
}

const sadece = role_name => (req, res, next) => {
  if(req.user.role_name&& req.user.role_name == role_name){
    
    next();
  }else{
    return res.status(403).json({message: "Bu, senin için değil"})
  }
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
}


const usernameVarmi = async (req, res, next) => {
 const {username} = req?.body//req varsa ?
 const checkUsername = await goreBul({username});
  if(checkUsername.length===0||!checkUsername){
    return res.status(401).json({message: "Geçersiz kriter"})
  }else{ req.user = checkUsername[0];
  
  next();}
}
   
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */



const rolAdiGecerlimi = (req, res, next) => {
  let { role_name } = req.body;


  if (!role_name) {
    req.body.role_name = "student";
    return next();
  }

  const role = role_name.trim();

  if (role === "admin") {
    return res.status(422).json({ message: "Rol adı admin olamaz" });
  }

  if (role.length === 0) {
    req.body.role_name = "student";
    return next();
  }

  if (role.length > 32) {
    return res.status(422).json({ message: "rol adı 32 karakterden fazla olamaz" });
  }

  req.body.role_name = role;

  next();
  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
}

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
}
