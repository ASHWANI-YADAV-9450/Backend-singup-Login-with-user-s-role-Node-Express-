const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");


const userSchema = new mongoose.Schema({

    name:{
        type:String,
        required:[true,"Please Enter Your Name"],
        maxLength:[30,"Name cannot exceed 30 characters"],
        minLength:[4,"Name should have more than 4 characters"]
    },
    middleName:{
        type:String,
        required:[false,"Please Enter Your Middle Name"],
        maxLength:[30,"Name cannot exceed 30 characters"],
    },
    lastName:{
        type:String,
        required:[false,"Please Enter Your last Name"],
        maxLength:[30,"Name cannot exceed 30 characters"],
    },
    password:{
        type:String,
        required:[true,"Please Enter Your Password"],
        minLength:[8,"Password should be greater than 8 characters"],
        select:false,
    },
    countryName:{
        type:String,
        required:[true,"Please Enter Your Country Name"],
        maxLength:[30,"Cannot exceed 30 characters"]
    },
    phone:{
        type:Number,
        required:[true,"Please Enter Your Phone Number"],
        maxLength:[10,"Cannot exceed 10 Numbers"],
        minLength:[10,"Should have 10 Numbers"]
    },
    email:{
        type:String,
        required:[true,"Please Enter Your Email"],
        unique:true,
        validator:[validator.isEmail,"Please Enter a valid Email"]
    },
    
        role:{
            type:String,
            required: [true,"Please Enter admin || user || agent"],
            enum:["admin","user","agent"]
          },
          createdAt: {
            type: Date,
            default: Date.now,
          },

          resetPasswordToken: String,
          resetPasswordExpire: Date,
});

userSchema.pre("save",async function(next){   // here we use function because in arrow function we cannot use this

    

    this.password = await bcrypt.hash(this.password,10);
    // this.role = await bcrypt.hash(this.role,10 );

})

// JWT TOKEN
userSchema.methods.getJWTToken = function (){
    return jwt.sign({id:this._id},process.env.JWT_SECRET,{
        expiresIn: process.env.JWT_EXPIRE,
    });
}

//Compare Password
userSchema.methods.comparePassword = async function(enteredPassword){
    return await bcrypt.compare(enteredPassword,this.password);
}



module.exports = mongoose.model("User", userSchema);