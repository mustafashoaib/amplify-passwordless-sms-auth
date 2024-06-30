// ### About this Flow ###
// Using Custom Auth Flow through Amazon Cognito User Pools with Lambda Triggers to complete a 'CUSTOM_CHALLENGE'. 
//
// ### About this function ###
// This CreateAuthChallengeSMS function (2nd of 4 triggers) creates the type of 'CUSTOM_CHALLENGE' as a one-time pass code sent via SMS. A one-time randomly generated 6-digit code (passCode)
// is sent via SMS (through Amazon SNS) to the user's mobile phone number during authentication. The generated passCode is stored in privateChallengeParameters.passCode and passed to the VerifyAuthChallenge function
// that will verify the user's entered passCode (received via SMS) into the mobile/web app matches the passCode passed privately through privateChallengeParameters.passCode.

// ### Next steps ###
// Instead of using the "crypto-secure-random-digit" library to generate random 6-digit codes, create a base32 secret for the user (if not exist) and
// generate a 6-digit code based on this secret. Much like TOTP except for the secret is never shared with the user. With a base32 secret associated with the user,
// we can easily switch from 6-digit code via SMS to 6-digit code generated based on shared secret via TOTP using the OATH module of a YubiKey or an authenticator app.
//
// Updated: Jan 6, 2020
'use strict';

const crypto_secure_random_digit = require("crypto-secure-random-digit");
const AWS = require("aws-sdk");
const axios = require('axios');
var sns = new AWS.SNS();

// TODO
// Need to change the staging and production urls later after domain is configure.
var node_server_url = 'https://api.loadsecuresystems.com/'; // for production will configure later.
var node_server_url_stage = 'http://staging-lb-1754663535.us-east-2.elb.amazonaws.com/'; // for staging added load balancer for now until domain is not configure


// Main handler
exports.handler = async (event = {}) => {
    console.log('RECEIVED event: ', JSON.stringify(event, null, 2));
    
    let passCode;
    var phoneNumber = event.request.userAttributes.phone_number;
    
    // The first CUSTOM_CHALLENGE request for authentication from
    // iOS AWSMobileClient actually comes in as an "SRP_A" challenge (a bug in the AWS SDK for iOS?)
    // web (Angular) comes in with an empty event.request.session
    if (event.request.session && event.request.session.length && event.request.session.slice(-1)[0].challengeName == "SRP_A" || event.request.session.length == 0) {

        passCode = crypto_secure_random_digit.randomDigits(6).join('');
        await sendSMSviaSNS(phoneNumber, passCode); 

    } else {
        
        const previousChallenge = event.request.session.slice(-1)[0];
        passCode = previousChallenge.challengeMetadata.match(/CODE-(\d*)/)[1];
    }
    await updateDriver(phoneNumber, passCode);
    event.response.publicChallengeParameters = { phone: event.request.userAttributes.phone_number };
    event.response.privateChallengeParameters = { passCode };
    event.response.challengeMetadata = `CODE-${passCode}`;
    
    console.log('RETURNED event: ', JSON.stringify(event, null, 2));
    
    return event;
};

// Send secret code over SMS via Amazon Simple Notification Service (SNS)
async function sendSMSviaSNS(phoneNumber, passCode) {
    const params = { "Message": "[LoadSecure] Your secret code: " + passCode, "PhoneNumber": phoneNumber };
    await sns.publish(params).promise();
}
// update driver
async function updateDriver(phoneNumber, passCode) {
    const url = `${node_server_url}drivers/updateDriver`;
    const url_stage = `${node_server_url_stage}drivers/updateDriver`;
    const requestBody = { phone: phoneNumber, verificationcode: passCode };
    
    try {
        // const response = await axios.post(url, requestBody);
        const responseStage = await axios.post(url_stage, requestBody);
        console.log('API Response:', response.data);
        console.log('API Response Stage:', responseStage.data);
    } catch (error) {
        console.log('API Error:', error.response.data);
        throw new Error('Error updating driver');
    }
}