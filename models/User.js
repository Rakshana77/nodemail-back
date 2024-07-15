import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: {
        type: String,
        default:"visitor"
    }
})

const UserModel = mongoose.model("User", UserSchema)



export default UserModel;
