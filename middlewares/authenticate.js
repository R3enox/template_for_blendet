import User from "../db/userModel.js";
import bcrypt from "bcrypt";

export async function authenticate(req, res, next) {
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
