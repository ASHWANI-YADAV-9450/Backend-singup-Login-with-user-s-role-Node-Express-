const ErrorHandler = require("../utils/errorhandler");
const User = require("../models/userModel");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const sendToken = require("../utils/jwtToken");
const crypto = require("crypto");


// Registrater a user 
exports.registerUser = catchAsyncErrors( async(req,res,next)=>{

    const { name,middleName,lastName,password,countryName,phone, email,  role} = req.body;
  
  const user = await User.create({
    name,middleName,lastName,password,countryName,phone,email,role
   
      });
  
      sendToken(user,200,res);
  });
  
  
  // Login User
  exports.loginUser = catchAsyncErrors (async (req,res,next)=>{
  
      const { email , password, role} = req.body;
  
      //checking if user has given password and email both
  
      if (!email || !password || !role) {
          return next(new ErrorHandler("Please Enter Email , Password & role", 400));
        }
  
        const user = await User.findOne({ email, role}).select("+password");
  
        if (!user) {
          return next(new ErrorHandler("Invalid email or role", 401));
        }
  
        const isPasswordMatched = await user.comparePassword(password); 
        
        if (!isPasswordMatched) {
          return next(new ErrorHandler("Invalid  password", 401));
        }
        
     sendToken(user,200,res);
  });
  
  // Logout User
  exports.logout = catchAsyncErrors(async (req, res, next) =>{
  
      res.cookie("token",null, {
          expires: new Date(Date.now()),
          httpOnly:true,
      });
  
      res.status(200).json({
          success: true,
          message: "Logged Out",
      });
  });