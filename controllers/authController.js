import bcrypt from "bcrypt";
import User from "../db/userModel.js";

export async function register(req, res) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) return res.status(409).send({ message: "Email in use" });

    const hashPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({ email, password: hashPassword });

    res.status(201).send({ newUser });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
}

export async function login(req, res) {}

export function getUser(req, res) {
  try {
    const { user } = req;
    res.send({ user });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
}
