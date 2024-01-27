import User from "../db/userModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;

export async function authentiBase(req, res, next) {
  try {
    const headers = req.headers.authorization.split(" ")[1];
    const [email, password] = Buffer.from(headers, "base64")
      .toString()
      .split(":");
    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).send({ message: "Invalid username or password" });
    const isMath = await bcrypt.compare(password, user.password);
    if (!isMath)
      return res.status(401).send({ message: "Invalid username or password" });
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ message: "Not authorized" });
    console.log(error);
  }
}

export async function authenticate(req, res, next) {
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, JWT_SECRET, async (error, data) => {
    try {
      if (error) {
        throw new Error("Invalid token");
      }
      const user = await User.findById(data.id);
      if (user.token !== token) {
        throw new Error("Invalid user");
      }
      req.user = user;
      next();
    } catch (error) {
      res.status(401).send({ message: error.message });
      console.log(error);
    }
  });
}
