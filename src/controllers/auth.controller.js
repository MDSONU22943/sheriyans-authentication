import userModel from "../models/user.mode.js";
import crypto from "crypto"
import jwt from "jsonwebtoken"
import config from "../config/config.js"
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import {generateOtp, getOtpHtml} from "../utils/utils.js"
import otpModel from '../models/otp.model.js';

export async function register(req,res){
    const {username, email, password} = req.body;

    const isAlreadyRegistered = await userModel.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(isAlreadyRegistered){
        return res.status(409).json({
            success: false,
            message: "Username or email already exists"
        })
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })

    const refreshToken = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "7d"})

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.create({user:user._id, refreshToken: refreshTokenHash, ip: req.ip, userAgent: req.headers["user-agent"]})

    const accessToken = jwt.sign({id: user._id,sessionId: session._id}, config.JWT_SECRET, {expiresIn: "15m"})

    

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    // console.log(accessToken==refreshToken)
    const otp=generateOtp()
    const html=getOtpHtml(otp)
    const otpHash=crypto.createHash("sha256").update(otp).digest("hex")
    await otpModel.create({email:user.email, user:user._id, otpHash})

    await sendEmail(user.email, "OTP Verification",`Your otp code is ${otp}`, html)

    return res.status(201).json({
        success: true,
        message: "User registered successfully",
        user:{
            username:user.username,
            email:user.email,
            verified:user.verified
        },
        
    })
}

export async function getMe(req,res){
    const token = req.headers.authorization?.split(" ")[1]

    if(!token){
        return res.status(401).json({
            success: false,
            message: "Token Not Found"
        })
    }

    const decoded = jwt.verify(token, config.JWT_SECRET)
    const user = await userModel.findById(decoded.id)

    if(!user){
        return res.status(404).json({
            success: false,
            message: "User Not Found"
        })
    }

    res.status(200).json({
        success: true,
        user
    })



    
}

export async function refreshToken(req,res){
    const refreshToken = req.cookies.refreshToken

    if(!refreshToken){
        return res.status(401).json({
            success: false,
            message: "Refresh Token Not Found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET)
    
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.findOne({refreshTokenHash, revoked:false})

    if(!session){
        return res.status(401).json({
            message:"Invalid refresh token"
        })
    }


    const accessToken = jwt.sign({id: decoded.id}, config.JWT_SECRET, {expiresIn: "15m"})

    const newRefreshToken = jwt.sign({id: decoded.id}, config.JWT_SECRET, {expiresIn: "7d"})

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex")

    session.refreshTokenHash=newRefreshTokenHash
    await session.save()

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.status(200).json({
        success: true,
        message: "Access Token Refreshed Successfully",
        accessToken
    })
}

export async function logout(req,res){
    const refreshToken= req.cookies.refreshToken

    if(!refreshToken){
        return res.status(401).json({
            success: false,
            message: "Refresh Token Not Found"
        })
    }

    const refreshTokenHash= crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session=await sessionModel.findOne({refreshToken: refreshTokenHash, revoked: false})

    if(!session){
        return res.status(400).json({
            message: "Invalid Session or refresh Token"
        })
    }

    session.revoked=true
    await session.save()

    res.clearCookie("refreshToken")

    res.status(200).json({
        success: true,
        message: "Logged out successfully"
    })
}

export async function logoutAll(req,res){
    const refreshToken= req.cookies.refreshToken

    if(!refreshToken){
        return res.status(401).json({
            success: false,
            message: "Refresh Token Not Found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET)

    await sessionModel.updateMany({user: decoded.id, revoked: false}, {revoked: true})

    res.clearCookie("refreshToken")

    res.status(200).json({
        success: true,
        message: "Logged out from all devices successfully"
    })
}

export async function login(req,res){
    const {email, password} = req.body

    const user = await userModel.findOne({email})

    if(!user){
        return res.status(404).json({
            success: false,
            message: "User Not Found"
        })
    }

    if(!user.verified){
        return res.status(401).json({
            success: false,
            message: "Email not verified"
        })
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")

    if(hashedPassword !== user.password){
        return res.status(401).json({
            success: false,
            message: "Invalid Password"
        })
    }

    const refreshToken = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "7d"})

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.create({user:user._id, refreshToken: refreshTokenHash, ip: req.ip, userAgent: req.headers["user-agent"]})

    const accessToken = jwt.sign({id: user._id}, config.JWT_SECRET, {expiresIn: "15m"})

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    return res.status(200).json({
        success: true,
        message: "Logged in successfully",
        accessToken
    })

}

export async function verifyEmail(req,res){
    const {email, otp} = req.body

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex")

    const otpDoc = await otpModel.findOne({email, otpHash})

    if(!otpDoc){
        return res.status(400).json({
            success: false,
            message: "Invalid OTP"
        })
    }

    

    const user=await userModel.findByIdAndDelete(otpDoc.user,{verified:true})

    await otpModel.deleteMany({user: otpDoc.user})

    return res.status(200).json({
        message: "Email verified successfully",
        user:{
            username:user.username,
            email:user.email,
            verified:user.verified
        }
    })


}