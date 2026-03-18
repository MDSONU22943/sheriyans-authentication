function generateOtp(){
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function getOtpHtml(otp){
    return `<h1>Your OTP Code</h1>
    <p>Your OTP code is: <strong>${otp}</strong></p>
    <p>This code will expire in 10 minutes.</p>
    <p>If you did not request this code, please ignore this email.</p>
    <p>Thank you!</p>`
}

export {generateOtp, getOtpHtml}