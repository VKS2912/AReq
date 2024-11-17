const express = require('express');
const router = express.Router();
const cfunction = require('../Function.js');
const FimeApi = require('../FimeAPI');
const config = require('../../config/ServerConfig.js');
const { v4: uuidv4 } = require('uuid');
const fnOtp = require('../Otp.js');
const system = require('os');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const ECKey = require('ec-key');
const jose = require('node-jose');
const base64url = require('base64url');
const { find, updateOne, insert, insertOne, findOne , updateOneWithParam} = require('../../Db/MongoOperation.js');
const { HSMProcess, fnM0HSM, fnM2HSM } = require('../HSM.js');
const request = require("request");
const ApiRecordsCollection = config.MongoConfig.ApiRecordsCollection;
const Blacklist = config.MongoConfig.BlackListCollection;
const ClientsCollection = config.MongoConfig.ClientCollection;
const TransactionRule = config.MongoConfig.TransactionRule;



router.post("/", function (req, res) {
    setTimeout(() => { fnApiTimeout(); }, config.TimeoutConfig.AReqTimeOut);
    let hrtimeTotal = process.hrtime();
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "post, get, put");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");

    let ReqUUID = uuidv4();
    let InitiateInsert = true;
    let threeDSServerTransID = "";
    let vAccNo = "";
    let vExpiryDate = "";
    let vReqData = {};
    let CardData;
    let vDeviceInfo;
    cfunction.fnPrintLogs('info', ' AReq called uuid = ' + ReqUUID, process.pid);
    req.headers.encStatus = req.body != undefined && req.body.encData != undefined ? true : false;
    let reqHeader = req.headers;
    let contentTypeValue = reqHeader['content-type'].split(";");
    let contentTypeVal = (contentTypeValue != undefined && contentTypeValue[0] != undefined) ? contentTypeValue[0].toLowerCase() : "";
    let contentTypeChar = (contentTypeValue != undefined && contentTypeValue[1] != undefined) ? contentTypeValue[1].toLowerCase() : "";
    let x_forwarded_for = req.header('x-forwarded-for');
    x_forwarded_for = (x_forwarded_for != undefined) ? x_forwarded_for.split(",") : [];
    x_forwarded_for = x_forwarded_for[0];
    cfunction.fnPrintLogs('info', ' AReq contentTypeVal = ' + contentTypeVal, process.pid);
    cfunction.fnPrintLogs('info', ' AReq contentTypeChar = ' + contentTypeChar, process.pid);
    let headerVal = (contentTypeVal == "application/json" && contentTypeChar == "charset=utf-8") ? true : false;

    if (headerVal) {

        cfunction.fnRequestDecryption(x_forwarded_for, req, ReqUUID, req.headers.encStatus, function (cbData) {
            if (cbData.success) {
                vReqData = cfunction.AReqValidation(cbData.data);
                vReqData.serverUrl = x_forwarded_for != undefined ? x_forwarded_for : req.hostname;
                vReqData.DirectoryServer = cfunction.fnFindDs(vReqData.serverUrl);

                vAccNo = vReqData.AreqData.acctNumber;
                cfunction.fnPrintLogs('debug', 'AReq Request vAccNo = ' + vAccNo, " acctNumber===" + vReqData.AreqData.acctNumber);
                vReqData.AreqData.acctNumber = cfunction.Encryption(vAccNo);
                vDeviceInfo = vReqData.AreqData.deviceInfo;
                vReqData.AreqData.deviceInfo = cfunction.Encryption(vReqData.AreqData.deviceInfo);
                cfunction.findAtn(function (atnData) {
                    if (atnData) {
                        vReqData.AreqData.AuthenticationTrackingNumber = atnData;

                        vExpiryDate = vReqData.AreqData.cardExpiryDate;
                        vReqData.AreqData.cardExpiryDate = cfunction.Encryption(vExpiryDate);
                        for (let key in vReqData.AreqData) {
                            vReqData[key] = vReqData.AreqData[key];
                        }

                        delete vReqData.AreqData["sdkEphemPubKey"];
                        threeDSServerTransID = vReqData.threeDSServerTransID;

                        let vQuery = {};
                        vQuery.AcsTransID = ReqUUID;
                        vQuery.threeDSServerTransID = threeDSServerTransID;
                        vQuery.Host = system.hostname();
                        vQuery.Datetime = new Date();
                        vQuery.Status = "New";
                        vQuery.ApiName = "AReq";
                        vQuery.ApiData = vReqData.AreqData;
                        vQuery.Type = "Request";
                        vQuery.ErrorCode = "200";

                        let hrtime = process.hrtime();

                        insertOne(vQuery, ApiRecordsCollection, handleAPIInsertSuc, handleAPIInsertErr);
                        function handleAPIInsertSuc(insertResult) {
                            cfunction.fnPrintLogs('warn', 'AReq insertOne (seconds, nanoseconds) = ' + process.hrtime(hrtime), '');
                            cfunction.fnPrintLogs('info', 'AReq Request Inserted For uuid = ' + ReqUUID, '');
                            cfunction.fnPrintLogs('debug', 'AReq Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult) + " vReqData.RequestStatus===" + JSON.stringify(vReqData));
                            delete vReqData.AreqData;
                            vReqData.Ds = vReqData.DirectoryServer;//cfunction.NetworkMessageType(vAccNo);
                            // if (vReqData.Ds == "Visa" && vReqData.threeRIInd != undefined) {
                            //     if (vReqData.threeRIInd != "06" && vReqData.threeRIInd != "11" && vReqData.threeRIInd != "80") {
                            //         vReqData.RequestStatus = false;
                            //         vReqData.transStatusReason = "12";
                            //     }
                            // }
                            if (!config.ds[vReqData.Ds]) {
                                vReqData.acsTransID = ReqUUID;
                                cfunction.fnPrintLogs('info', vReqData.Ds + ' Network InActive in config ' + ReqUUID, '');
                                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                let errRes = cfunction.fnErrorResponse(vReqData, 11);
                                fnAReqResponseProcess(errRes, "Error");
                            } else if (vReqData.RequestStatus) {
                                vReqData.acctNumber = vAccNo;
                                vReqData.cardExpiryDate = vExpiryDate;
                                vReqData.acsTransID = ReqUUID;
                                fnAReqRequestProcess(vReqData);
                            } else {
                                vReqData.acsTransID = ReqUUID;
                                cfunction.fnPrintLogs('info', 'AReq validation failed For uuid = ' + ReqUUID, '');
                                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                let errRes = cfunction.fnErrorResponse(vReqData, 5);
                                fnAReqResponseProcess(errRes, "Error");
                            }
                        }

                        function handleAPIInsertErr(insertErr) {
                            cfunction.fnPrintLogs('error', ' handleAPIInsertErr For uuid = ' + ReqUUID, insertErr);
                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                            let errRes = cfunction.fnErrorResponse(vReqData, 17);
                            if (!res._headerSent) {
                                cfunction.fnPrintLogs('debug', ' handleAPIInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                                cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                    cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                                    res.send(cbData.data).end();
                                });
                            }
                        }
                    } else {
                        cfunction.fnPrintLogs('error', 'AReq failed atn failed ' + ReqUUID, '');
                        cfunction.fnPrintLogs('error', 'request failed here ' + ReqUUID, '');
                        let errRes = cfunction.fnErrorResponse(vReqData, 17);
                        if (!res._headerSent) {
                            cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                res.send(cbData.data).end();
                            });
                        }
                    }
                });

            } else {
                cfunction.fnPrintLogs('info', 'AReq Request data decryption failed For uuid = ' + ReqUUID, '');
                let vQuery = {};
                vQuery.AcsTransID = ReqUUID;
                vQuery.Host = system.hostname();
                vQuery.Datetime = new Date();
                vQuery.Status = "New";
                vQuery.ApiName = "AReq";
                vQuery.ApiData = req.body;
                vQuery.Type = "Request";
                vQuery.ErrorCode = "302";

                if (vQuery.ApiName != null && vQuery.Status != null) {
                    let matrics = {};
                    matrics.ApiName = vQuery.ApiName;
                    matrics.Status = vQuery.Status;
                    cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vQuery.ApiName + " " + vQuery.Status + JSON.stringify(matrics), '');
                }

                insertOne(vQuery, ApiRecordsCollection, handleAPIInsertSuc2, handleAPIInsertErr2);
                function handleAPIInsertSuc2(insertResult) {
                    cfunction.fnPrintLogs('info', 'AReq Request Inserted For uuid = ' + ReqUUID, '');
                    cfunction.fnPrintLogs('debug', 'AReq Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                    cfunction.fnPrintLogs('info', 'AReq validation failed For uuid = ' + ReqUUID, '');
                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                    vReqData.messageType = "AReq";
                    let errRes = cfunction.fnErrorResponse(vReqData, 10);
                    fnAReqResponseProcess(errRes, "Error");
                }

                function handleAPIInsertErr2(insertErr) {
                    cfunction.fnPrintLogs('error', ' handleAPIInsertErr2 For uuid = ' + ReqUUID, insertErr);
                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                    let errRes = cfunction.fnErrorResponse(vReqData, 17);
                    if (!res._headerSent) {
                        cfunction.fnPrintLogs('debug', ' handleAPIInsertErr2 res sent For uuid = ' + JSON.stringify(errRes), '');
                        cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                            cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                            res.send(cbData.data).end();
                        });
                    }
                }
            }


            function fnAReqRequestProcess(vReqData) {
                cfunction.fnPrintLogs('info', ' function fnAReqRequestProcess called ', '');
                cfunction.fnPrintLogs('debug', ' function fnAReqRequestProcess called vReqData : ' + JSON.stringify(vReqData), '');

                let hrtime = process.hrtime();
                //Card details api
                fnOtp.getCardDetailsIssuer(vReqData.acctNumber, ReqUUID, function (err, cbData) {

                    cfunction.fnPrintLogs('warn', 'Process Time to find getCardDetailsIssuer (seconds, nanoseconds) = ' + process.hrtime(hrtime), '');
                    cfunction.fnPrintLogs('warn', 'Memory Usage to find getCardDetailsIssuer (heapUsed in mb) = ' + (process.memoryUsage().heapUsed / 1048576).toFixed(2) + " MB", '');

                    if (err) {
                        cfunction.fnPrintLogs('error', ' getCardDetailsIssuer ', err);
                        cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                        let errRes = cfunction.fnErrorResponse(vReqData, 17);
                        fnAReqResponseProcess(errRes, "Error");
                    } else {
                        let tmpAcctNumber = cfunction.Encryption(vReqData.acctNumber.toString().trim());
                        let vcard = cfunction.EncryptionOld(vReqData.acctNumber.toString().trim());
                        //let isChallengeFlow = false;
                         cfunction.fnRba(vReqData, tmpAcctNumber, vcard, cbData, function (isChallengeFlow) {
                            findOne({ CardNumber: { $in: [tmpAcctNumber, vcard] }, IsBlacklisted: true }, 'Blacklist', handleFindOneBlacklistSuccess, handleFindOneBlacklistErr);
                        
                            function handleFindOneBlacklistErr(err) {
                                cfunction.fnPrintLogs('error', ' Blacklist Finding Error in Blacklist record for' + err);
                                cfunction.fnPrintLogs('error', 'Blacklist Finding Error in Blacklist record for ', err.stack);
                                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                let errRes = cfunction.fnErrorResponse(vReqData, 17);
                                fnAReqResponseProcess(errRes, "Error");
                            }

                            function handleFindOneBlacklistSuccess(vres) {

                                cfunction.fnPrintLogs('debug', 'getCardDetailsIssuer cbData : ', JSON.stringify(cbData));

                                CardData = cbData.data;
                                vReqData.phone = CardData.MobileNumber;
                                vReqData.email = CardData.EmailAddress;
                                vReqData.OTPMode = CardData.OTPMode;
                                vReqData.OTPLength = CardData.OTPLength;
                                vReqData.CAVVKeyGen = CardData.CAVVKeyGen;
                                vReqData.ResendOTPTime = CardData.ResendOTPTime;
                                vReqData.CReqTimeOut = CardData.CReqTimeOut;
                                vReqData.cardholderInfo = CardData.cardholderInfo;
                                vReqData.BankingUrl = CardData.BankingUrl;
                                vReqData.OTPGeneration = CardData.OTPGeneration;
                                vReqData.OTPDelivery = CardData.OTPDelivery;
                                let IssuerObject = cfunction.getIssuerKeys(CardData, BigInt(vReqData.acctNumber));
                                vReqData.IssuerKeys = IssuerObject != undefined ? IssuerObject : {};
                                vReqData.InstitutionId = CardData.InstitutionId;
                                vReqData.ClientId = CardData.ClientId;
                                vReqData.CountryCode = CardData.CountryCode;
                                vReqData.threeDS = CardData.threeDS;
                                vReqData.CardData = CardData.CardData;
                                vReqData.cardProcessing = CardData.cardProcessing != undefined ? CardData.cardProcessing : {};

                                let TxnsChallenge = true;
                                let BinNumber = vReqData.acctNumber != undefined ? cfunction.getBigInt(vReqData.acctNumber) : 0;
                                let CardRange = CardData.CardRange != undefined ? CardData.CardRange : {};

                                for (let i = 0; i < CardRange.length; i++) {
                                    for (let j = 0; j < CardRange[i].ranges.length; j++) {
                                        if (BinNumber >= CardRange[i].ranges[j].min && BinNumber <= CardRange[i].ranges[j].max) {
                                            TxnsChallenge = CardRange[i].challenge != undefined ? CardRange[i].challenge : true;
                                        }
                                    }
                                }

                                let cardStatus = cbData.data != undefined && cbData.data.Status != undefined ? cbData.data.Status : "";
                                let cardStatusR = cbData.data != undefined && cbData.data.StatusReason != undefined ? cbData.data.StatusReason : "06";
                                if (vres != null) {
                                    cfunction.fnPrintLogs('error', ' Account is blacklisted ', JSON.stringify(vres));
                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                    cardStatus = "Failed";
                                    cardStatusR = "09";
                                }
                                if (vReqData.CardData && vReqData.OTPDelivery == "Acs") {
                                    if (vReqData.OTPMode == "mail" && (vReqData.email == undefined || vReqData.email == null || vReqData.email == "")) {
                                        cfunction.fnPrintLogs('error', 'Email is not available', "");
                                        cardStatus = "Failed";
                                        cardStatusR = "08";
                                    } else if (vReqData.OTPMode == "phone" && (vReqData.phone == undefined || vReqData.phone == null || vReqData.phone == "")) {
                                        cfunction.fnPrintLogs('error', 'Phone no is not available', err);
                                        cardStatus = "Failed";
                                        cardStatusR = "08";
                                    } else if (vReqData.OTPMode == "both") {
                                        if (vReqData.email == undefined || vReqData.email == null || vReqData.email == "") {
                                            cfunction.fnPrintLogs('error', 'Email is not available', "");
                                            cardStatus = "Failed";
                                            cardStatusR = "08";
                                        }
                                        if (vReqData.phone == undefined || vReqData.phone == null || vReqData.phone == "") {
                                            cfunction.fnPrintLogs('error', 'Phone no is not available', err);
                                            cardStatus = "Failed";
                                            cardStatusR = "08";
                                        }
                                    }
                                }

                                if (config.FimeCertification) {
                                    if ((vReqData.cardProcessing.flow == "na" || vReqData.cardProcessing.transStatus == "na" || vReqData.cardProcessing.flow == undefined) && vReqData.cardProcessing.transStatus != "I") {
                                        cardStatus = "InActive";
                                    }
                                }

                                if (vReqData.DirectoryServer == "Amex" && config.amexCert != undefined && config.amexCert.amexCert && config.amexCert[vReqData.acctNumber.toString().trim()] != undefined && config.amexCert[vReqData.acctNumber.toString().trim()].TranStatus == "N") {
                                    cardStatus = config.amexCert[vReqData.acctNumber.toString().trim()].cardStatus;
                                    cfunction.fnPrintLogs('debug', ' cardStatus for AMEX= ' + cardStatus, '');
                                }
                                if (vReqData.DirectoryServer == "Visa" && config.visaCert != undefined && config.visaCert.visaCert && config.visaCert[vReqData.acctNumber.toString().trim()] != undefined) {
                                    cardStatus = config.visaCert[vReqData.acctNumber.toString().trim()].cardStatus;
                                    cardStatusR = config.visaCert[vReqData.acctNumber.toString().trim()].TranStatusReason;
                                    cfunction.fnPrintLogs('debug', ' cardStatus for Visa= ' + cardStatus, '');
                                }
                                let additionalChallangeByCountry = "NA";
                                if (vReqData.DirectoryServer == "Visa") {
                                    cfunction.fnPrintLogs('info', ' check country for Visa= ', '');
                                    additionalChallangeByCountry = cfunction.fncheckCountry(vReqData.merchantCountryCode, vReqData.threeDSRequestorChallengeInd, vReqData.threeDSRequestorAuthenticationInd);
                                    cfunction.fnPrintLogs('debug', ' additionalChallangeByCountry for Visa= ' + additionalChallangeByCountry, '');
                                    if (config.visaCert != undefined && config.visaCert.visaCert && (vReqData.acctNumber.toString() == "4012000000007052" || vReqData.acctNumber.toString() == "4012000000007128")) {
                                        cardStatus = "InActive";
                                        cardStatusR = "90";
                                    }
                                }
                                if (cardStatus.toLowerCase() != "active" && config.FimeCertification && vReqData.cardProcessing.flow == undefined) {
                                    cfunction.fnPrintLogs('info', ' card data not found ', '');
                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                    let errRes = cfunction.fnErrorResponse(vReqData, 13);
                                    errRes.errorDetail = "acctNumber";
                                    fnAReqResponseProcess(errRes, "Error");
                                } else if (((!CardData.CardData && (cbData.success || cbData.success == "true")) || (CardData.CardData && (cbData.success || cbData.success == "true"))) && cardStatus.toLowerCase() == "active") {
                                    if (vReqData.DirectoryServer == "Amex" && config.amexCert != undefined && config.amexCert.amexCert) {
                                        vReqData["threeDSRequestorChallengeInd"] = config.amexCert[vReqData.acctNumber.toString().trim()].threeDSRequestorChallengeInd;
                                        if (vReqData.threeDSRequestorDecReqInd == "Y") {
                                            vReqData["threeDSRequestorChallengeInd"] = "01"
                                        }
                                        vReqData.threeDS = config.amexCert[vReqData.acctNumber.toString().trim()].threeDS;

                                        cfunction.fnPrintLogs('debug', ' threeDSRequestorChallengeInd for AMEX= ' + vReqData["threeDSRequestorChallengeInd"], '');
                                    }
                                    let fnCheckChallegeReq = cfunction.fnCheckChallegeReq(vReqData.threeDSRequestorChallengeInd);
                                    if (config.visaCert != undefined && config.visaCert.visaCert && vReqData.acctNumber.toString() == "4012000000001238") {
                                        fnCheckChallegeReq = "Y"
                                    }
                                    vReqData.threeDS = vReqData.threeDS != undefined ? vReqData.threeDS : true;
                                    if (config.FimeCertification && (vReqData.cardProcessing.flow == "frictionless" && fnCheckChallegeReq == "" || vReqData.threeDSRequestorChallengeInd == "06")) {
                                        fnFrictionlessFlow(CardData);
                                    } else if (config.FimeCertification && (vReqData.cardProcessing.flow == "challenge" || vReqData.cardProcessing.flow == "decoupled")) {
                                        fnChallangeFlow(CardData);
                                    } else if (additionalChallangeByCountry != "NA") {
                                        fnChallangeFlow(CardData);
                                    } else if (fnCheckChallegeReq == "N") {
                                        fnFrictionlessFlow(CardData);
                                    } else if (fnCheckChallegeReq == "Y") {
                                        fnChallangeFlow(CardData);
                                    } else if (isChallengeFlow){
                                        fnChallangeFlow(CardData);
                                    }
                                    else if (vReqData.Ds == "Npci" && vReqData.threeDSRequestorAuthenticationInd == "81") {
                                        fnEmiOptionsProcess(CardData);
                                    } else if (vReqData.Ds == "Npci" && vReqData.threeDSRequestorAuthenticationInd == "83") {
                                        fnChallangeFlow(CardData);
                                    } else if (vReqData.Ds == "Visa" && (vReqData.threeDSRequestorChallengeInd == "82")) {
                                        fnFrictionlessFlow(CardData);
                                    } else if (vReqData.Ds == "Amex" && (vReqData.threeDSRequestorAuthenticationInd == "81")) {
                                        fnFrictionlessFlow(CardData);
                                    } else if (vReqData.Ds == "Amex" && vReqData.threeDSRequestorAuthenticationInd == "80") {
                                        fnChallangeFlow(CardData);
                                    } else if (!TxnsChallenge || TxnsChallenge == "false") {
                                        fnFrictionlessFlow(CardData);
                                    } else if (vReqData.deviceChannel == "03" && vReqData.threeDSRequestorDecReqInd != "Y") {
                                        fnFrictionlessFlow(CardData);
                                    } else {
                                        fnChallangeFlow(CardData);
                                    }

                                } else {
                                    cfunction.fnPrintLogs('info', ' card verification failed ', '');
                                    cfunction.fnPrintLogs('debug', ' card verification failed ', 'CardData.CardData :' + CardData.CardData + ' cbData.succes ' + cbData.succes + ' cardStatus ' + cardStatus);
                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                    let vFailedStatusFlow = {};
                                    // cardStatusR = "06";
                                    if (vReqData.Ds == "Mastercard") {
                                        vFailedStatusFlow.eci = "00"
                                    } else if (vReqData.Ds == "Visa" || vReqData.Ds == "Npci") {
                                        vFailedStatusFlow.eci = "07"
                                    } else if (vReqData.Ds == "Amex") {
                                        vFailedStatusFlow.eci = "07"
                                        cardStatusR = "04";
                                    } else {
                                        vFailedStatusFlow.eci = "";
                                    }

                                    vFailedStatusFlow.threeDSServerTransID = vReqData.threeDSServerTransID;

                                    // DS assigned ACS identifier.
                                    if (vReqData.Ds == "Mastercard") {
                                        vFailedStatusFlow.acsOperatorID = config.acsOperatorID.Mastercard;
                                        vFailedStatusFlow.acsReferenceNumber = config.acsReferenceNumber.Mastercard;
                                    } else if (vReqData.Ds == "Visa") {
                                        vFailedStatusFlow.acsOperatorID = config.acsOperatorID.Visa;
                                        vFailedStatusFlow.acsReferenceNumber = config.acsReferenceNumber.Visa;
                                    } else if (vReqData.Ds == "Amex") {
                                        vFailedStatusFlow.acsOperatorID = config.acsOperatorID.Amex;
                                        vFailedStatusFlow.acsReferenceNumber = config.acsReferenceNumber.Amex;
                                    } else if (vReqData.Ds == "Npci") {
                                        vFailedStatusFlow.acsOperatorID = config.acsOperatorID.Npci;
                                        vFailedStatusFlow.acsReferenceNumber = config.acsReferenceNumber.Npci;
                                    } else {
                                        vFailedStatusFlow.acsOperatorID = "";
                                        vFailedStatusFlow.acsReferenceNumber = "";
                                    }
                                    vFailedStatusFlow.acsTransID = ReqUUID; //acs unique id; //ucaf data // need to check

                                    if (vReqData.dsReferenceNumber != undefined && vReqData.dsReferenceNumber != null && vReqData.dsReferenceNumber != "") {
                                        vFailedStatusFlow.dsReferenceNumber = vReqData.dsReferenceNumber;
                                    }
                                    if (vReqData.dsTransID != undefined && vReqData.dsTransID != null && vReqData.dsTransID != "") {
                                        vFailedStatusFlow.dsTransID = vReqData.dsTransID;
                                    }
                                    if (vReqData.messageExtension != undefined && vReqData.messageExtension != null && vReqData.messageExtension != "") {
                                        vFailedStatusFlow.messageExtension = vReqData.messageExtension;
                                    }

                                    if (vReqData.purchaseCurrency != undefined && vReqData.purchaseCurrency != null && vReqData.purchaseCurrency != "") {
                                        vFailedStatusFlow.purchaseCurrency = vReqData.purchaseCurrency;
                                    }

                                    vFailedStatusFlow.messageType = "ARes";

                                    if (vReqData.messageVersion != undefined && vReqData.messageVersion != null && vReqData.messageVersion != "") {
                                        vFailedStatusFlow.messageVersion = vReqData.messageVersion;
                                    }
                                    if (vReqData.sdkTransID != undefined && vReqData.sdkTransID != null && vReqData.sdkTransID != "") {
                                        vFailedStatusFlow.sdkTransID = vReqData.sdkTransID;
                                    }

                                    if (cardStatus == "Expired" || (vReqData.cardProcessing != undefined && (vReqData.cardProcessing.flow == "na" || vReqData.cardProcessing.transStatus == "na"))) {
                                        vFailedStatusFlow.transStatus = "U"; //Y/N/U/A/C/D/R
                                        vFailedStatusFlow.transStatusReason = cardStatusR;
                                    } else if (cardStatus == "Failed") {
                                        vFailedStatusFlow.transStatus = "R"; //Y/N/U/A/C/D/R
                                        vFailedStatusFlow.transStatusReason = cardStatusR;
                                    } else {
                                        vFailedStatusFlow.transStatus = "N"; //Y/N/U/A/C/D/R
                                        vFailedStatusFlow.transStatusReason = cardStatusR;
                                    }

                                    return fnAReqResponseProcess(vFailedStatusFlow, "Done"); //need to handle
                                }

                            }
                        });
                    
                    }

                });
            }

            function fnEmiOptionsProcess(CardData) {
                let mesExt = [{
                    "name": "EMI_OPTIONS",
                    "id": (vReqData.acsTransID + "_EMI_O" + Math.floor(Math.random() * 9999 + 1000)),
                    "criticalityIndicator": true,
                    "data": { "emiDetails": CardData.emiDetails }
                }];
                let vResponceEmiOptions = {};
                if (vReqData.threeDSServerTransID != undefined && vReqData.threeDSServerTransID != null && vReqData.threeDSServerTransID != "") {
                    vResponceEmiOptions.threeDSServerTransID = vReqData.threeDSServerTransID;
                }
                if (vReqData.Ds == "Mastercard") {
                    vResponceEmiOptions.acsOperatorID = config.acsOperatorID.Mastercard;
                    vResponceEmiOptions.acsReferenceNumber = config.acsReferenceNumber.Mastercard;
                } else if (vReqData.Ds == "Visa") {
                    vResponceEmiOptions.acsOperatorID = config.acsOperatorID.Visa;
                    vResponceEmiOptions.acsReferenceNumber = config.acsReferenceNumber.Visa;
                } else if (vReqData.Ds == "Amex") {
                    vResponceEmiOptions.acsOperatorID = config.acsOperatorID.Amex;
                    vResponceEmiOptions.acsReferenceNumber = config.acsReferenceNumber.Amex;
                } else if (vReqData.Ds == "Npci") {
                    vResponceEmiOptions.acsOperatorID = config.acsOperatorID.Npci;
                    vResponceEmiOptions.acsReferenceNumber = config.acsReferenceNumber.Npci;
                } else {
                    vResponceEmiOptions.acsOperatorID = "";
                    vResponceEmiOptions.acsReferenceNumber = "";
                }
                vResponceEmiOptions.acsTransID = ReqUUID;
                if (vReqData.dsReferenceNumber != undefined && vReqData.dsReferenceNumber != null && vReqData.dsReferenceNumber != "") {
                    vResponceEmiOptions.dsReferenceNumber = vReqData.dsReferenceNumber;
                }
                if (vReqData.dsTransID != undefined && vReqData.dsTransID != null && vReqData.dsTransID != "") {
                    vResponceEmiOptions.dsTransID = vReqData.dsTransID;
                }

                if (vReqData.purchaseCurrency != undefined && vReqData.purchaseCurrency != null && vReqData.purchaseCurrency != "") {
                    vResponceEmiOptions.purchaseCurrency = vReqData.purchaseCurrency;
                }
                vResponceEmiOptions.messageType = "ARes";

                if (vReqData.messageVersion != undefined && vReqData.messageVersion != null && vReqData.messageVersion != "") {
                    vResponceEmiOptions.messageVersion = vReqData.messageVersion;
                }
                if (vReqData.sdkTransID != undefined && vReqData.sdkTransID != null && vReqData.sdkTransID != "") {
                    vResponceEmiOptions.sdkTransID = vReqData.sdkTransID;
                }
                vResponceEmiOptions.transStatus = "I";
                vResponceEmiOptions.transStatusReason = "81";
                vResponceEmiOptions.messageExtension = mesExt;
                return fnAReqResponseProcess(vResponceEmiOptions, "Done");
            }

            function fnChallangeFlow(CardData) {
                updateVelocity(CardData);
                
                let pro_matrics = {};
                pro_matrics.Flow = "Challange_Flow";
                cfunction.fnPrintLogs('info', ' function fnChallangeFlow called ', '', pro_matrics);
                let vTransstatus = "";
                let vResponceChallenge = {};
                if (config.FimeCertification) {
                    vTransstatus = CardData.cardProcessing.flow == "challenge" || vReqData.threeDSRequestorDecReqInd != "Y" ? "C" : "D";
                    vReqData.threeDSRequestorDecReqInd = CardData.cardProcessing.flow == "challenge" ? "N" : vReqData.threeDSRequestorDecReqInd;
                } else {
                    vTransstatus = vReqData.threeDSRequestorDecReqInd == "Y" && config.acsDecConInd == "Y" ? "D" : "C";
                }
                if (vTransstatus == "D") {
                    vResponceChallenge.cardholderInfo = "Additional authentication required";
                }
                let vAcsChallengeMandated = "Y";

                if (vReqData.threeDSServerTransID != undefined && vReqData.threeDSServerTransID != null && vReqData.threeDSServerTransID != "") {
                    vResponceChallenge.threeDSServerTransID = vReqData.threeDSServerTransID;
                }

                vResponceChallenge.acsChallengeMandated = vAcsChallengeMandated; //Y or N
                vResponceChallenge.acsDecConInd = ((vReqData.threeDSRequestorDecReqInd != undefined && vReqData.threeDSRequestorDecReqInd == "Y" && config.acsDecConInd == "Y") ? "Y" : "N"); //Y or N

                if (vReqData.Ds == "Mastercard") {
                    vResponceChallenge.acsOperatorID = config.acsOperatorID.Mastercard;
                    vResponceChallenge.acsReferenceNumber = config.acsReferenceNumber.Mastercard;
                } else if (vReqData.Ds == "Visa") {
                    vResponceChallenge.acsOperatorID = config.acsOperatorID.Visa;
                    vResponceChallenge.acsReferenceNumber = config.acsReferenceNumber.Visa;
                } else if (vReqData.Ds == "Amex") {
                    vResponceChallenge.acsOperatorID = config.acsOperatorID.Amex;
                    vResponceChallenge.acsReferenceNumber = config.acsReferenceNumber.Amex;
                } else if (vReqData.Ds == "Npci") {
                    vResponceChallenge.acsOperatorID = config.acsOperatorID.Npci;
                    vResponceChallenge.acsReferenceNumber = config.acsReferenceNumber.Npci;
                } else {
                    vResponceChallenge.acsOperatorID = "";
                    vResponceChallenge.acsReferenceNumber = "";
                }
                vResponceChallenge.acsTransID = ReqUUID; //acs unique id

                if (vReqData.Ds == "Amex" && (vReqData.threeDSRequestorAuthenticationInd == "80" && vReqData.messageCategory == "02")) {

                    let mesExt = [{
                        "name": "Membership Rewards",
                        "id": (vReqData.acsTransID + "_" + Math.floor(Math.random() * 9999 + 1000)),
                        "criticalityIndicator": false,
                        "data": {
                            "mrBalance": CardData.mrBalance != undefined ? CardData.mrBalance : "1000",
                            "mrCurrencyName": "Membership Rewards",
                            "conversionPoints": CardData.conversionPoints != undefined ? CardData.conversionPoints : "1000",
                            "convertedCurrAmount": CardData.convertedCurrAmount != undefined ? CardData.convertedCurrAmount : "10",
                            "mrStatusReason": "01",
                        }
                    }];
                    vTransstatus = "Y";
                    vResponceChallenge.messageExtension = mesExt;
                } else if (vReqData.Ds == "Npci" && vReqData.threeDSRequestorAuthenticationInd == "83") {
                    let mesExt = [{
                        "name": "Bridging",
                        "id": (vReqData.acsTransID + "_" + Math.floor(Math.random() * 9999 + 1000)),
                        "criticalityIndicator": false,
                        "data": {
                            "addData": {
                                "cardSecurityCodeStatus": "Y",
                                "cardSecurityCodeStatusSource": "02"
                            }
                        }
                    }];
                    vResponceChallenge.messageExtension = mesExt;
                } else if (vReqData.messageExtension != undefined && vReqData.messageExtension != null && vReqData.messageExtension != "") {
                    vResponceChallenge.messageExtension = vReqData.messageExtension;
                }


                if (vTransstatus == "C" || vTransstatus == "D") {
                    vResponceChallenge.authenticationType = vTransstatus == "C" ? "02" : "04"; //01 = Static• 02 = Dynamic• 03 = OOB• 04 = Decoupled• 05–79 = Reserved
                }

                if (vReqData.broadInfo != undefined && vReqData.broadInfo != null && vReqData.broadInfo != "") {
                    vResponceChallenge.broadInfo = vReqData.broadInfo;
                }

                if (vTransstatus == "D" && vReqData.cardholderInfo) {
                    vResponceChallenge.cardholderInfo = vReqData.cardholderInfo;
                }

                if (vReqData.dsReferenceNumber != undefined && vReqData.dsReferenceNumber != null && vReqData.dsReferenceNumber != "") {
                    vResponceChallenge.dsReferenceNumber = vReqData.dsReferenceNumber;
                }
                if (vReqData.dsTransID != undefined && vReqData.dsTransID != null && vReqData.dsTransID != "") {
                    vResponceChallenge.dsTransID = vReqData.dsTransID;
                }

                if (vReqData.purchaseCurrency != undefined && vReqData.purchaseCurrency != null && vReqData.purchaseCurrency != "") {
                    vResponceChallenge.purchaseCurrency = vReqData.purchaseCurrency;
                }

                vResponceChallenge.messageType = "ARes";
                if (vReqData.messageVersion != undefined && vReqData.messageVersion != null && vReqData.messageVersion != "") {
                    vResponceChallenge.messageVersion = vReqData.messageVersion;
                }
                if (vReqData.sdkTransID != undefined && vReqData.sdkTransID != null && vReqData.sdkTransID != "") {
                    vResponceChallenge.sdkTransID = vReqData.sdkTransID;
                }
                vResponceChallenge.transStatus = vTransstatus; //Y/N/U/A/C/D/R

                if (vTransstatus == "N" || vTransstatus == "U" || vTransstatus == "R") {
                    vResponceChallenge.transStatusReason = "14";
                }

                if (vTransstatus == "C" && vReqData.BankingUrl != "" && vReqData.BankingUrl != undefined && vReqData.BankingUrl != null) {
                    vResponceChallenge.cardholderInfo = cfunction.fnGenIBUrl(vReqData, vReqData.BankingUrl);
                    vReqData.BankingUrl = vResponceChallenge.cardholderInfo;
                }

                let acsURL = config.AcsServerC.completeUrl + "/CReq";

                let sdkInterface = vReqData.deviceRenderOptions != undefined && vReqData.deviceRenderOptions.sdkInterface != undefined ? vReqData.deviceRenderOptions.sdkInterface : "";
                let sdkUiType = vReqData.deviceRenderOptions != undefined && vReqData.deviceRenderOptions.sdkUiType != undefined ? vReqData.deviceRenderOptions.sdkUiType : "";

                if (vReqData.deviceChannel == "01") {
                    cfunction.fnPrintLogs('info', ' function app condition called ', '');
                    if (config.visaCert != undefined && config.visaCert.visaCert && vReqData.acctNumber.toString() == "4012000000001105") {
                        let vDinfo = base64url.decode(vDeviceInfo);
                        let mesExt = [{
                            "name": "Device Acknowledgment",
                            "id": "A000000802-001",//(vReqData.acsTransID + "_" + Math.floor(Math.random() * 9999 + 1000)),
                            "criticalityIndicator": false,
                            "data": {
                                "version": "1.0",
                                "authenticationMethod": "10",
                                "deviceInfoRecognisedVersion": JSON.parse(vDinfo)["DV"],
                                "deviceUserInterfaceMode": "01"
                            }
                        }];
                        vResponceChallenge.messageExtension = mesExt;
                        cfunction.fnPrintLogs('debug', ' vResponceChallenge:======== ', JSON.stringify(vDinfo));
                    }
                    let certificateData = cfunction.fnGetCertificateData("", "", "", vReqData.DirectoryServer);

                    let acsPrivateKey = fs.readFileSync(__dirname + '/../../Certificates/' + certificateData.key);
                    acsPrivateKey = cfunction.decryptionValue(acsPrivateKey.toString("hex"));
                    let acsPublicKey = fs.readFileSync(__dirname + '/../../Certificates/' + certificateData.cert);
                    // let acsPublicCa = fs.readFileSync(__dirname + '/../../Certificates/' + certificateData.ca);
                    let acsPubliccert1;
                    let acsPubliccert2;
                    acsPubliccert1 = fs.readFileSync(__dirname + '/../../Certificates/' + certificateData.cert1);
                    acsPubliccert2 = fs.readFileSync(__dirname + '/../../Certificates/' + certificateData.cert2);


                    let acsPassphrase = certificateData.passphrase;

                    cfunction.fnPrintLogs('debug', ' acsPrivateKey: ' + acsPrivateKey + ' acsPublicKey: ' + acsPublicKey, ' passphrase: ' + acsPassphrase);

                    let acsEphemKey = ECKey.createECKey('P-256');

                    let acsEphemPubKey = acsEphemKey.asPublicECKey().toJSON();
                    cfunction.fnPrintLogs('debug', ' step1 acsEphemKey: ', JSON.stringify(acsEphemKey));
                    cfunction.fnPrintLogs('debug', ' step1 acsEphemPubKey: ', JSON.stringify(acsEphemPubKey));
                    try {
                        vReqData.sdkEphemPubKey = JSON.parse(vReqData.sdkEphemPubKey);
                    } catch (e) {
                        cfunction.fnPrintLogs('error', ' function app condition called for Json parse error ', e);
                    }
                    cfunction.fnPrintLogs('debug', ' step2 sdkEphemPubKey: ', JSON.stringify(vReqData.sdkEphemPubKey));
                    if (vReqData.sdkEphemPubKey.crv == "P-256") {
                        cfunction.fnPrintLogs('debug', ' correct processing for crv: ', '');
                    }//else need to block the processing and report error

                    let computeSecret = acsEphemKey.computeSecret(new ECKey(vReqData.sdkEphemPubKey)).toString('hex');
                    cfunction.fnPrintLogs('debug', 'computeSecret: ' + computeSecret, ReqUUID);
                    let keySecretObj = cfunction.fnGenKeySecret(computeSecret, vReqData.sdkReferenceNumber);
                    vReqData.keySecret = keySecretObj["256"];
                    vReqData.keySecret128 = keySecretObj["128"];
                    cfunction.fnPrintLogs('debug', 'step3 keySecret: ' + vReqData.keySecret, ReqUUID);
                    cfunction.fnPrintLogs('debug', 'step3 keySecret128: ' + vReqData.keySecret128, ReqUUID);

                    let acsSignedContent = { "acsEphemPubKey": acsEphemPubKey, "sdkEphemPubKey": vReqData.sdkEphemPubKey, "acsURL": acsURL };

                    cfunction.fnPrintLogs('debug', ' step4 acsSignedContent: ', JSON.stringify(acsSignedContent));

                    let claims = { alg: 'PS256', "x5c": [cfunction.toBase64url(acsPublicKey.toString("utf8").toString('base64')), cfunction.toBase64url(acsPubliccert1.toString("utf8").toString('base64')), cfunction.toBase64url(acsPubliccert2.toString("utf8").toString('base64'))] };
                    jose.JWK.asKey(acsPrivateKey, 'pem', { passphrase: "C0recard" }).then((key) => {
                        jose.JWS.createSign({ format: 'compact', fields: claims }, key).update(JSON.stringify(acsSignedContent), 'utf8')
                            .final()
                            .then((jws) => {
                                cfunction.fnPrintLogs('debug', ' final step jws response ', jws);
                                cfunction.fnPrintLogs('debug', ' final step jws header response ', JSON.stringify(jws.header));
                                vResponceChallenge.acsSignedContent = jws;
                                if (config.FimeCertification && vReqData.cardProcessing.AcsRenderingType != undefined) {
                                    let uiTemplate = "";
                                    if (sdkUiType[0] == "01" || sdkUiType[0] == "02" || sdkUiType[0] == "03" || sdkUiType[0] == "04" || sdkUiType[0] == "05") {
                                        uiTemplate = sdkUiType[0];
                                    }
                                    else {
                                        uiTemplate = "01";
                                    }
                                    vResponceChallenge.acsRenderingType = {
                                        "acsInterface": (vReqData.cardProcessing.AcsRenderingType).substring(0, 2),
                                        "acsUiTemplate": ((vReqData.cardProcessing.AcsRenderingType).substring(2, 4) != undefined && (vReqData.cardProcessing.AcsRenderingType).substring(2, 4) != "") ? (vReqData.cardProcessing.AcsRenderingType).substring(2, 4) : uiTemplate
                                    };
                                } else {
                                    vResponceChallenge.acsRenderingType = {
                                        "acsInterface": (sdkInterface == "01" ? "01" : "02"),
                                        "acsUiTemplate": (sdkUiType[0] == "01" || sdkUiType[0] == "02" || sdkUiType[0] == "03" || sdkUiType[0] == "04" || sdkUiType[0] == "05" ? sdkUiType[0] : "01")
                                    };
                                }
                                fnAReqResponseProcess(vResponceChallenge, "Done");
                            }).catch((err) => {
                                console.error('Signing failed:', err);
                                if (err) {
                                    cfunction.fnPrintLogs('error', ' jwt sign err : ', err);
                                }
                                fnAReqResponseProcess(vResponceChallenge, "Done");
                            });
                    }).catch((err) => {
                        console.error('Key conversion failed:', err);
                    });
                    /* jwt.sign(acsSignedContent, { key: acsPrivateKey.toString(), passphrase: acsPassphrase }, { algorithm: 'RS256', header: claims, keyid: ReqUUID }, function (err, signature) {
                        if (err) {
                            cfunction.fnPrintLogs('error', ' jwt sign err : ', err);
                        } else {
                            cfunction.fnPrintLogs('debug', ' final step jws response ', signature);
                            vResponceChallenge.acsSignedContent = signature;
                            if (config.FimeCertification && vReqData.cardProcessing.AcsRenderingType != undefined) {
                                let uiTemplate = "";
                                if (sdkUiType[0] == "01" || sdkUiType[0] == "02" || sdkUiType[0] == "03" || sdkUiType[0] == "04" || sdkUiType[0] == "05") {
                                    uiTemplate = sdkUiType[0];
                                }
                                else {
                                    uiTemplate = "01";
                                }
                                vResponceChallenge.acsRenderingType = {
                                    "acsInterface": (vReqData.cardProcessing.AcsRenderingType).substring(0, 2),
                                    "acsUiTemplate": ((vReqData.cardProcessing.AcsRenderingType).substring(2, 4) != undefined && (vReqData.cardProcessing.AcsRenderingType).substring(2, 4) != "") ? (vReqData.cardProcessing.AcsRenderingType).substring(2, 4) : uiTemplate
                                };
                            } else {
                                vResponceChallenge.acsRenderingType = {
                                    "acsInterface": (sdkInterface == "01" ? "01" : "02"),
                                    "acsUiTemplate": (sdkUiType[0] == "01" || sdkUiType[0] == "02" || sdkUiType[0] == "03" || sdkUiType[0] == "04" || sdkUiType[0] == "05" ? sdkUiType[0] : "01")
                                };
                            }
                        }
                        return fnAReqResponseProcess(vResponceChallenge, "Done");
                    }); */
                } else {
                    vResponceChallenge.acsURL = acsURL;

                    return fnAReqResponseProcess(vResponceChallenge, "Done");
                }
            }

            function fnFrictionlessFlow(CardData) {
                insertVelocity(CardData);
                let pro_matrics = {};
                pro_matrics.Flow = "Frictionless_Flow";
                cfunction.fnPrintLogs('info', ' function fnFrictionlessFlow called ', '', pro_matrics);

                let vResponceFrictionless = {};

                let vTransstatus = vReqData.threeDS ? "A" : "Y"; 

                if (vReqData.threeDSRequestorChallengeInd == "05" || vReqData.threeDSRequestorChallengeInd == "06" || vReqData.threeDSRequestorChallengeInd == "07" || vReqData.threeDSRequestorChallengeInd == "82") { vTransstatus = "I"; }
                if (config.visaCert != undefined && config.visaCert.visaCert && (vReqData.acctNumber.toString() == "4012000000007268" || vReqData.acctNumber.toString() == "0000000000007268")) {
                    let mesExt = [{
                        "name": "Bridging",
                        "id": "A000000802-004",//(vReqData.acsTransID + "_" + Math.floor(Math.random() * 9999 + 1000)),
                        "criticalityIndicator": false,
                        "data": {
                            "version": "2.0",
                            "addData": {
                                "transChallengeExemption": "05"
                            }
                        }
                    }];
                    vResponceFrictionless.messageExtension = mesExt;
                }
                if (vReqData.threeDSServerTransID != undefined && vReqData.threeDSServerTransID != null && vReqData.threeDSServerTransID != "") {
                    vResponceFrictionless.threeDSServerTransID = vReqData.threeDSServerTransID;
                }

                vResponceFrictionless.whiteListStatus = (vReqData.whiteListStatus != undefined && vReqData.whiteListStatus != "") ? vReqData.whiteListStatus : "U";
                vResponceFrictionless.whiteListStatusSource = (vReqData.whiteListStatus != undefined && vReqData.whiteListStatus != "") ? "02" : "03";

                if (vReqData.Ds == "Mastercard") {
                    vResponceFrictionless.acsOperatorID = config.acsOperatorID.Mastercard;
                    vResponceFrictionless.acsReferenceNumber = config.acsReferenceNumber.Mastercard;
                } else if (vReqData.Ds == "Visa") {
                    vResponceFrictionless.acsOperatorID = config.acsOperatorID.Visa;
                    vResponceFrictionless.acsReferenceNumber = config.acsReferenceNumber.Visa;
                } else if (vReqData.Ds == "Amex") {
                    vResponceFrictionless.acsOperatorID = config.acsOperatorID.Amex;
                    vResponceFrictionless.acsReferenceNumber = config.acsReferenceNumber.Amex;
                } else if (vReqData.Ds == "Npci") {
                    vResponceFrictionless.acsOperatorID = config.acsOperatorID.Npci;
                    vResponceFrictionless.acsReferenceNumber = config.acsReferenceNumber.Npci;
                } else {
                    vResponceFrictionless.acsOperatorID = "";
                    vResponceFrictionless.acsReferenceNumber = "";
                }

                if (config.FimeCertification) { delete vResponceFrictionless.acsOperatorID; }

                let isDSA = false;
                vResponceFrictionless.acsTransID = ReqUUID; //acs unique id
                let tmpInfoData = cfunction.fnInfoData(vReqData.merchantName);
                if (vReqData.Ds == "Mastercard") {
                    vResponceFrictionless.eci = vTransstatus == "Y" ? "02" : "01";
                } else if (vReqData.Ds == "Visa" || vReqData.Ds == "Amex") {
                    if (vTransstatus == "Y") {
                        vResponceFrictionless.eci = "05";
                    } else if (vTransstatus == "A") {
                        vResponceFrictionless.eci = "06";
                    } else {
                        vResponceFrictionless.eci = "07";
                    }
                } else if (vReqData.Ds == "Npci") {
                    vResponceFrictionless.eci = "05";
                }

                if (vReqData.dsReferenceNumber != undefined && vReqData.dsReferenceNumber != null && vReqData.dsReferenceNumber != "") {
                    vResponceFrictionless.dsReferenceNumber = vReqData.dsReferenceNumber;
                }
                if (vReqData.dsTransID != undefined && vReqData.dsTransID != null && vReqData.dsTransID != "") {
                    vResponceFrictionless.dsTransID = vReqData.dsTransID;
                }
                if (vReqData.messageExtension != undefined && vReqData.messageExtension != null && vReqData.messageExtension != "") {
                    vResponceFrictionless.messageExtension = vReqData.messageExtension;
                    vReqData.messageExtension.forEach(element => {
                        if (element.name == "DAF Extension") { isDSA = true }
                    });
                }

                if (vReqData.purchaseCurrency != undefined && vReqData.purchaseCurrency != null && vReqData.purchaseCurrency != "") {
                    vResponceFrictionless.purchaseCurrency = vReqData.purchaseCurrency;
                }

                vResponceFrictionless.messageType = "ARes";

                if (vReqData.messageVersion != undefined && vReqData.messageVersion != null && vReqData.messageVersion != "") {
                    vResponceFrictionless.messageVersion = vReqData.messageVersion;
                }
                if (vReqData.sdkTransID != undefined && vReqData.sdkTransID != null && vReqData.sdkTransID != "") {
                    vResponceFrictionless.sdkTransID = vReqData.sdkTransID;
                }
                if (vReqData.Ds == "Amex" && (vReqData.threeDSRequestorAuthenticationInd == "80" || vReqData.threeDSRequestorAuthenticationInd == "81")) {
                    vResponceFrictionless.authenticationType = vReqData.threeDSRequestorAuthenticationInd;
                } else {
                    vResponceFrictionless.authenticationType = "01";
                }
                let authenticationMethod = vReqData.Ds != undefined && vReqData.Ds == "Npci" ? "99" : "10";
                if (vReqData.Ds == "Amex") {
                    authenticationMethod = vReqData.Ds != undefined && vReqData.Ds == "Amex" ? "00" : "10";
                }
                if (vReqData.Ds == "Visa") {
                    authenticationMethod = vReqData.Ds != undefined && vReqData.Ds == "Visa" ? "99" : "10";

                }

                vResponceFrictionless.transStatus = vTransstatus; //Y/N/U/A/C/D/R
                let vData = { transStatus: vTransstatus, authenticationMethod: authenticationMethod, purchaseAmount: vReqData.purchaseAmount, purchaseCurrency: vReqData.purchaseCurrency, purchaseDate: vReqData.purchaseDate == undefined ? new Date().getTime() : vReqData.purchaseDate, merchantname: tmpInfoData, acctNumber: vReqData.acctNumber, CAVVKeyGen: vReqData.CAVVKeyGen, cardExpiryDate: vReqData.cardExpiryDate, dsTransID: vReqData.dsTransID, ECI: vResponceFrictionless.eci, IssuerKeys: vReqData.IssuerKeys, messageCategory: vReqData.messageCategory, threeDSRequestorAuthenticationInd: vReqData.threeDSRequestorAuthenticationInd, messageVersion: vReqData.messageVersion, AuthenticationTrackingNumber: vReqData.AuthenticationTrackingNumber, isDSA: isDSA };
                cfunction.fnUcafData(vData, function (err, uData) {
                    cfunction.fnPrintLogs('debug', 'function fnUcafData response with ' + uData, '');
                    if (uData == "") {
                        vResponceFrictionless.transStatus = "U";
                        vResponceFrictionless.transStatusReason = "14";
                        return fnAReqResponseProcess(vResponceFrictionless, "Error");
                    } else {
                        vResponceFrictionless.authenticationValue = uData;
                        if (vResponceFrictionless.transStatus == "Y") {
                            vResponceFrictionless.transStatusReason = "17";
                        }
                        return fnAReqResponseProcess(vResponceFrictionless, "Done");
                    }
                });


            }

            function fnAReqResponseProcess(reqProData, status) {

                cfunction.fnPrintLogs('info', ' function fnAReqResponseProcess called ', '');
                cfunction.fnPrintLogs('debug', ' function fnAReqResponseProcess called reqProData : ' + JSON.stringify(reqProData) + ' status : ' + status, '');

                reqProData.deviceChannel = vReqData.deviceChannel;
                reqProData.purchaseAmount = vReqData.purchaseAmount;
                if (reqProData.authenticationType != null && reqProData.authenticationType != undefined)
                    reqProData.authenticationType = reqProData.authenticationType;

                if (vReqData.Ds == "Mastercard") {
                    vReqData.DsId = config.acsOperatorID.Mastercard
                } else if (vReqData.Ds == "Visa") {
                    vReqData.DsId = config.acsOperatorID.Visa
                } else if (vReqData.Ds == "Amex") {
                    vReqData.DsId = config.acsOperatorID.Amex
                } else if (vReqData.Ds == "Npci") {
                    vReqData.DsId = config.acsOperatorID.Npci
                } else {
                    vReqData.DsId = "";
                }

                let AReqFind = { AcsTransID: ReqUUID, ApiName: "AReq", Status: "New" };
                let vErrorCode = (status == "Done") ? "0000" : "0" + reqProData.errorCode;
                let AReqUpdateData;
                if (reqProData.errorCode == "101") {
                    AReqUpdateData = { $set: { "Status": status, "InstitutionId": vReqData.InstitutionId, "ClientId": vReqData.ClientId, "DirectoryServer": vReqData.DirectoryServer, "DsId": vReqData.DsId, "Originator": vReqData.serverUrl, "CountryCode": vReqData.CountryCode, "ErrorCode": vErrorCode } };
                } else {
                    AReqUpdateData = { $set: { "Status": status, "InstitutionId": vReqData.InstitutionId, "ClientId": vReqData.ClientId, "DirectoryServer": vReqData.DirectoryServer, "DsId": vReqData.DsId, "Originator": vReqData.serverUrl, "CountryCode": vReqData.CountryCode, "ApiData.authenticationType": reqProData.authenticationType, "ApiData.transStatus": reqProData.transStatus, "ErrorCode": vErrorCode } };
                }
                cfunction.fnPrintLogs('info', 'Data for Prometheus AReq New' + JSON.stringify(AReqFind), '');

                updateOne(AReqFind, AReqUpdateData, ApiRecordsCollection, handleAReqUpdateSucc, handleAReqUpdateErr);

                function handleAReqUpdateSucc(fresult) {
                    cfunction.fnPrintLogs('info', ' function handleAReqUpdateSucc called ', '');
                    cfunction.fnPrintLogs('debug', ' function handleAReqUpdateSucc called with fresult : ' + JSON.stringify(fresult), '');

                    if (fresult.modifiedCount > 0 && !res._headerSent && InitiateInsert) {
                        InitiateInsert = false;
                        let vAResInsert = {};
                        vAResInsert.AcsTransID = ReqUUID;
                        vAResInsert.threeDSServerTransID = threeDSServerTransID;
                        vAResInsert.Host = system.hostname();
                        vAResInsert.Datetime = new Date();
                        vAResInsert.Status = status;
                        vAResInsert.ApiName = "ARes";
                        vAResInsert.ApiData = reqProData;
                        vAResInsert.Type = "Response";
                        vAResInsert.ErrorCode = vErrorCode;

                        vAResInsert.InstitutionId = vReqData.InstitutionId;
                        vAResInsert.ClientId = vReqData.ClientId;
                        vAResInsert.DirectoryServer = vReqData.DirectoryServer;
                        vAResInsert.Originator = vReqData.serverUrl
                        vAResInsert.DsId = vReqData.DsId;
                        vAResInsert.CountryCode = vReqData.CountryCode;

                        if (vAResInsert.ApiName != null && vAResInsert.Status != null) {
                            let matrics = {};
                            matrics.ApiName = vAResInsert.ApiName;
                            matrics.Status = vAResInsert.Status;
                            cfunction.fnPrintLogs('info', ' Data for Prometheus ' + vAResInsert.ApiName + " " + vAResInsert.Status + JSON.stringify(matrics), '');
                        }
                        let av = "";

                        if (vAResInsert.ApiData != undefined && vAResInsert.ApiData.authenticationValue != undefined && vAResInsert.ApiData.authenticationValue != "") {
                            av = vAResInsert.ApiData.authenticationValue;
                            vAResInsert.ApiData.authenticationValue = cfunction.Encryption(av);
                        }

                        insertOne(vAResInsert, ApiRecordsCollection, handleAResInsertSucc, handleAResInsertErr);

                        function handleAResInsertErr(insertErr) {
                            if (av != "") {
                                reqProData.authenticationValue = av;
                            }
                            cfunction.fnPrintLogs('error', ' handleAResInsertErr For uuid = ' + ReqUUID, insertErr);
                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                            let errRes = cfunction.fnErrorResponse(vReqData, 17);
                            if (!res._headerSent) {
                                cfunction.fnPrintLogs('debug', ' handleAResInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                                cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                    cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                                    res.send(cbData.data).end();
                                });
                            }
                        }

                        function handleAResInsertSucc(insertResult) {

                            if (av != "") {
                                reqProData.authenticationValue = av;
                            }

                            cfunction.fnPrintLogs('info', ' handleAResInsertSucc For uuid = ' + ReqUUID, '');
                            cfunction.fnPrintLogs('debug', ' handleAResInsertSucc For uuid = ' + ReqUUID, JSON.stringify(insertResult));

                            if (!res._headerSent) {
                                if (status == "Done" && reqProData.transStatus == "C") {

                                    let sessionData = {};
                                    sessionData.encStatus = req.headers.encStatus;
                                    sessionData.creq = "N";
                                    sessionData.expire = new Date().getTime() + parseInt(config.TimeoutConfig.InitialCReqTimeOut);
                                    sessionData.OTPGeneration = vReqData.OTPGeneration;
                                    sessionData.OTPDelivery = vReqData.OTPDelivery;
                                    sessionData.InstitutionId = vReqData.InstitutionId;
                                    sessionData.ClientId = vReqData.ClientId;
                                    sessionData.DirectoryServer = vReqData.DirectoryServer;
                                    sessionData.DsId = vReqData.DsId;
                                    sessionData.Originator = vReqData.serverUrl;
                                    sessionData.CountryCode = vReqData.CountryCode;
                                    sessionData.keySecret = vReqData.keySecret;
                                    sessionData.keySecret128 = vReqData.keySecret128;
                                    sessionData.phone = vReqData.phone;
                                    sessionData.email = vReqData.email;
                                    sessionData.challengeCounter = 0;
                                    sessionData.attemptCount = 0;
                                    sessionData.questionId = 0;
                                    sessionData.acsRenderingType = reqProData.acsRenderingType;
                                    sessionData.notificationURL = vReqData.notificationURL;
                                    sessionData.messageVersion = vReqData.messageVersion;
                                    sessionData.sdkTransID = vReqData.sdkTransID;
                                    sessionData.CardData = vReqData.CardData;
                                    sessionData.hsmToken = IssuerKeyObject.acsToken.enc;
                                    if (vReqData.deviceChannel == "01") {
                                        sessionData.acsInterface = reqProData.acsRenderingType != undefined ? reqProData.acsRenderingType.acsInterface : "";
                                    }

                                    setTimeout(cfunction.CheckTxnsTimeout, parseInt(config.TimeoutConfig.InitialCReqTimeOut) + 2000, ReqUUID, "05");

                                    let sessionInsert = {};
                                    sessionInsert.acsTransID = ReqUUID;
                                    sessionInsert.threeDSServerTransID = vReqData.threeDSServerTransID;
                                    sessionInsert.data = sessionData;
                                    sessionInsert.Status = "Active";
                                    sessionInsert.Pid = process.pid;
                                    sessionInsert.Datetime = new Date();
                                    insertOne(sessionInsert, "Sessions", sessionSucc, sessionErr);

                                    function sessionErr(insertErr) {
                                        cfunction.fnPrintLogs('error', ' sessionErr For uuid = ' + ReqUUID, insertErr);
                                        cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                        sendARes();
                                    }

                                    function sessionSucc(insertResult) {
                                        cfunction.fnPrintLogs('info', ' Areq sessionSucc For uuid = ' + ReqUUID, '');
                                        cfunction.fnPrintLogs('debug', ' Areq sessionSucc For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                                        sendARes();
                                    }
                                } else {
                                    sendARes();
                                }

                                function sendARes() {
                                    cfunction.fnRequestEncryption(reqProData, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                        if (!res._headerSent) {
                                            cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                                            cfunction.fnPrintLogs('debug', 'AReq time (seconds, nanoseconds) = ' + JSON.stringify(cbData.data), '');
                                            res.send(cbData.data).end();
                                        }
                                        cfunction.fnPrintLogs('info', ' Areq response sent = ' + ReqUUID, '');
                                        if (config.FimeCertification && reqProData.transStatus == "D") {

                                            let poReqObj = {
                                                "messageType": "pOrq",
                                                "messageVersion": vReqData.messageVersion,
                                                "p_messageVersion": "1.0.5",
                                                "threeDSServerTransID": threeDSServerTransID,
                                                "acsTransID": ReqUUID
                                            };

                                            FimeApi.pOrq(poReqObj, parseInt(vReqData.threeDSRequestorDecMaxTime) * 60 * 1000, 'https://agu1-3ds2-tester.fimeconnect.com/acs/porq', function (err, FimeData) {
                                                if (err) {
                                                    cfunction.fnPrintLogs('info', ' areq pOrq err = ' + err, '');
                                                    cfunction.fnPrintLogs('info', ' request failed ', '');
                                                    vReqData.transStatusReason = "14";
                                                    vReqData.transStatus = "U";
                                                    vReqData.challengeCancel = "03";
                                                    fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                } else {
                                                    cfunction.fnPrintLogs('debug', ' areq pOrq FimeData = ' + JSON.stringify(FimeData), '');
                                                    vReqData.authenticationType = "04";
                                                    if (FimeData.isOobSuccessful || FimeData.p_isOobSuccessful) {
                                                        vReqData.CAVVKeyGen = "ACS";
                                                        vReqData.transStatus = "Y";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    } else if (!FimeData.isOobSuccessful || !FimeData.p_isOobSuccessful) {
                                                        vReqData.transStatusReason = "01";
                                                        vReqData.transStatus = "N";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    } else {
                                                        cfunction.fnPrintLogs('info', ' areq pOrq timeout ', '');
                                                        cfunction.fnPrintLogs('info', ' request failed ', '');
                                                        vReqData.transStatusReason = "14";
                                                        vReqData.transStatus = "U";
                                                        vReqData.challengeCancel = "03";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    }
                                                }
                                            });

                                            function fnRReqProcessing(AReqData, result) {

                                                cfunction.fnPrintLogs('info', ' fnRReqProcessing called for uuid = ' + ReqUUID, "");
                                                cfunction.fnPrintLogs('info', ' fnRReqProcessing called with AReqData = ' + ReqUUID + ' result : ' + JSON.stringify(result), "");

                                                cfunction.fnRReqData(vReqData, AReqData, result, function (err, RReqData) {
                                                    if (err) {
                                                        cfunction.fnPrintLogs('error', ' fnRReqProcessing err called for uuid = ' + ReqUUID, err);
                                                    } else {
                                                        RReqData.purchaseAmount = vReqData.purchaseAmount;
                                                        RReqData.deviceChannel = vReqData.deviceChannel;
                                                        let vRReqInsert = {};
                                                        vRReqInsert.AcsTransID = ReqUUID;
                                                        vRReqInsert.threeDSServerTransID = threeDSServerTransID;
                                                        vRReqInsert.Host = system.hostname();
                                                        vRReqInsert.Datetime = new Date();
                                                        vRReqInsert.Status = "Done";
                                                        vRReqInsert.ApiName = "RReq";
                                                        vRReqInsert.ApiData = RReqData;
                                                        vRReqInsert.Type = "Request";
                                                        vRReqInsert.ErrorCode = "0000";
                                                        vRReqInsert.InstitutionId = vReqData.InstitutionId;
                                                        vRReqInsert.ClientId = vReqData.ClientId;
                                                        vRReqInsert.DirectoryServer = vReqData.DirectoryServer;
                                                        vRReqInsert.DsId = vReqData.DsId;
                                                        vRReqInsert.Originator = vReqData.serverUrl;
                                                        vRReqInsert.CountryCode = vReqData.CountryCode;

                                                        if (vRReqInsert.ApiName != null && vRReqInsert.Status != null) {
                                                            let Rmatrics = {};
                                                            Rmatrics.ApiName = vRReqInsert.ApiName;
                                                            Rmatrics.Status = vRReqInsert.Status;
                                                            cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRReqInsert.ApiName + " " + vRReqInsert.Status + JSON.stringify(Rmatrics), '');
                                                        }


                                                        insertOne(vRReqInsert, ApiRecordsCollection, handleRReqAPIInsertSuc, handleRReqAPIInsertErr);

                                                        function handleRReqAPIInsertSuc(insertResult) {
                                                            cfunction.fnPrintLogs('info', 'RReq Request Inserted For uuid = ' + ReqUUID, '');
                                                            cfunction.fnPrintLogs('debug', 'RReq Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));

                                                            cfunction.fnRequestEncryption(RReqData, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (encData) {
                                                                if (encData.success) {
                                                                    cfunction.fnSendRReqtoDs(AReqData.dsURL, AReqData.DirectoryServer, encData.data, function (cbData) {
                                                                        if (cbData.success) {
                                                                            cfunction.fnRequestDecryption(vReqData.serverUrl, cbData.data, ReqUUID, req.headers.encStatus, function (cbDataD) {
                                                                                if (cbDataD.data) {
                                                                                    cbDataD.data.deviceChannel = vReqData.deviceChannel;
                                                                                    cbDataD.data.purchaseAmount = vReqData.purchaseAmount;
                                                                                    cbDataD.data.purchaseCurrency = vReqData.purchaseCurrency;

                                                                                }
                                                                                let vRResInsert = {};
                                                                                vRResInsert.AcsTransID = ReqUUID;
                                                                                vRResInsert.threeDSServerTransID = threeDSServerTransID;
                                                                                vRResInsert.Host = system.hostname();
                                                                                vRResInsert.Datetime = new Date();
                                                                                vRResInsert.Status = "Done";
                                                                                vRResInsert.ApiName = "RRes";
                                                                                vRResInsert.ApiData = cbDataD.data;
                                                                                vRResInsert.Type = "Response";
                                                                                vRResInsert.ErrorCode = "0000";
                                                                                vRResInsert.InstitutionId = vReqData.InstitutionId;
                                                                                vRResInsert.ClientId = vReqData.ClientId;
                                                                                vRResInsert.DirectoryServer = vReqData.DirectoryServer;
                                                                                vRResInsert.DsId = vReqData.DsId;
                                                                                vRResInsert.Originator = vReqData.serverUrl
                                                                                vRResInsert.CountryCode = vReqData.CountryCode;
                                                                                if (vRReqInsert.ApiName != null && vRReqInsert.Status != null) {
                                                                                    let Rmatrics = {};
                                                                                    Rmatrics.ApiName = vRReqInsert.ApiName;
                                                                                    Rmatrics.Status = vRReqInsert.Status;
                                                                                    cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRReqInsert.ApiName + " " + vRReqInsert.Status + JSON.stringify(Rmatrics), '');
                                                                                }
                                                                                insertOne(vRResInsert, ApiRecordsCollection, handleRResAPIInsertSuc, handleRResAPIInsertErr);
                                                                                function handleRResAPIInsertSuc(insertResult) {

                                                                                    cfunction.fnPrintLogs('info', 'RRes Request Inserted For uuid = ' + ReqUUID, '');
                                                                                    cfunction.fnPrintLogs('debug', 'RRes Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));

                                                                                    let rresVal = cfunction.fnRresValidation(cbDataD.data, RReqData);

                                                                                    cfunction.fnPrintLogs('debug', 'rresVal response = ' + ReqUUID, JSON.stringify(rresVal));

                                                                                    vReqData.challengeCompletionInd = "Y";
                                                                                    if (!rresVal.RequestStatus) {
                                                                                        vReqData.transStatus = "N";
                                                                                        let errorCode = rresVal.errCode != undefined ? rresVal.errCode : 17;
                                                                                        if (errorCode == 5) {
                                                                                            vReqData.errorCode = rresVal.errorCode;
                                                                                            vReqData.errorDescription = rresVal.errorDescription;
                                                                                            vReqData.errorDetail = rresVal.errorDetail;
                                                                                        }

                                                                                        let errRes = cfunction.fnErrorResponse(vReqData, errorCode);;
                                                                                        errRes.errorMessageType = "RRes";
                                                                                        fnSendRResErrorMSGToDS(errRes);
                                                                                        cfunction.fnPrintLogs('debug', ' error request from ds for rreq ' + JSON.stringify(errRes), '');
                                                                                        cfunction.fnPrintLogs('debug', ' request failed ', ReqUUID);
                                                                                    }
                                                                                }

                                                                                function handleRResAPIInsertErr(insertErr) {
                                                                                    cfunction.fnPrintLogs('error', ' handleRResAPIInsertErr For uuid = ' + ReqUUID, insertErr);
                                                                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                                                    if (!res._headerSent) {
                                                                                        cfunction.fnPrintLogs('debug', ' handleRResAPIInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                        else {
                                                                            cfunction.fnPrintLogs('error', ' RReq fail to Response For uuid = ' + ReqUUID + " ,Error= " + JSON.stringify(cbData.data), "");
                                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                                            let verrcode = 17;
                                                                            let vReturnErroCode = (typeof cbData.data === 'string') ? cbData.data : cbData.data.code;
                                                                            cfunction.fnPrintLogs('error', ' RReq fail to Response For uuid = ' + ReqUUID + " ,Error= " + vReturnErroCode, "");

                                                                            if (vReturnErroCode == "ESOCKETTIMEDOUT" || vReturnErroCode == "ETIMEDOUT") {
                                                                                verrcode = 16;
                                                                            }
                                                                            let errRes = cfunction.fnErrorResponse(vReqData, verrcode);
                                                                            let vRResInsert = {};
                                                                            vRResInsert.AcsTransID = ReqUUID;
                                                                            vRResInsert.threeDSServerTransID = threeDSServerTransID;
                                                                            vRResInsert.Host = system.hostname();
                                                                            vRResInsert.Datetime = new Date();
                                                                            vRResInsert.Status = "Error";
                                                                            vRResInsert.ApiName = "RRes";
                                                                            vRResInsert.ApiData = cbData.data;
                                                                            vRResInsert.Type = "Response";
                                                                            vRResInsert.ErrorCode = errRes.errorCode;
                                                                            vRResInsert.InstitutionId = vReqData.InstitutionId;
                                                                            vRResInsert.ClientId = vReqData.ClientId;
                                                                            vRResInsert.DirectoryServer = vReqData.DirectoryServer;
                                                                            vRResInsert.DsId = vReqData.DsId;
                                                                            vRResInsert.Originator = vReqData.serverUrl;
                                                                            vRResInsert.CountryCode = vReqData.CountryCode;

                                                                            if (vRResInsert.ApiName != null && vRResInsert.Status != null) {
                                                                                let Rmatrics = {};
                                                                                Rmatrics.ApiName = vRResInsert.ApiName;
                                                                                Rmatrics.Status = vRResInsert.Status;
                                                                                cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRResInsert.ApiName + " " + vRResInsert.Status + JSON.stringify(Rmatrics), '');
                                                                            }
                                                                            insertOne(vRResInsert, ApiRecordsCollection, handleRResAPIInsertSuc1, handleRResAPIInsertErr1);
                                                                            function handleRResAPIInsertSuc1(insertResult) {
                                                                                cfunction.fnPrintLogs('info', 'RRes Fail Inserted For uuid = ' + ReqUUID, '');
                                                                                cfunction.fnPrintLogs('debug', 'RRes Fail  Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                                                                                fnSendRResErrorMSGToDS(errRes);
                                                                            }

                                                                            function handleRResAPIInsertErr1(insertErr) {
                                                                                cfunction.fnPrintLogs('error', ' handleRResAPIInsertErr1 RRes Fail  Inserted For uuid = ' + ReqUUID, insertErr);
                                                                                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                                                if (!res._headerSent) {
                                                                                    cfunction.fnPrintLogs('debug', ' handleRResAPIInsertErr1 RRes Fail  Inserted sent For uuid = ' + JSON.stringify(errRes), '');
                                                                                }
                                                                            }

                                                                        }
                                                                    });
                                                                }
                                                            });
                                                        }

                                                        function handleRReqAPIInsertErr(insertErr) {
                                                            cfunction.fnPrintLogs('error', ' handleRReqAPIInsertErr For uuid = ' + ReqUUID, insertErr);
                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                            if (!res._headerSent) {
                                                                cfunction.fnSessionUpdate(ReqUUID, sessionData, sstatus, function (err, SessionResResult) {
                                                                    let errRes = cfunction.fnErrorResponse(vReqData, 17);
                                                                    cfunction.fnPrintLogs('debug', ' handleRReqAPIInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                                                                    cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                                                        cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                                                                        res.send(cbData.data).end();
                                                                    });
                                                                });
                                                            }
                                                        }
                                                    }
                                                });

                                                function fnSendRResErrorMSGToDS(RResData) {
                                                    cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS called for uuid = ' + ReqUUID, "");
                                                    cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS called with RResData = ' + ReqUUID + ' result : ' + JSON.stringify(RResData), "");

                                                    cfunction.fnSendRReqtoDs(AReqData.dsURL, AReqData.DirectoryServer, RResData, function (cbData) {
                                                        if (cbData.success) {
                                                            cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS Decription Response for RResData = ' + ReqUUID + ' RRespData : ' + JSON.stringify(cbData), "");
                                                        }
                                                        else {
                                                            cfunction.fnPrintLogs('error', 'fnSendRResErrorMSGToDS RRes fail to Response For uuid = ' + ReqUUID + " ,Error= " + JSON.stringify(cbData), "");
                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                        }
                                                    })
                                                }
                                            }
                                        } else if (reqProData.transStatus == "D") {
                                            if (config.stressTesting || config.stressTesting == "true") {
                                                cfunction.fnPrintLogs('info', ' amex time condition ', '');
                                                cfunction.fnPrintLogs('info', ' request failed ', '');
                                                let vBin = vReqData.acctNumber;
                                                vBin = cfunction.getBigInt(vBin);


                                                cfunction.getClientCard(vBin, function (FindResult) {
                                                    cfunction.fnPrintLogs('info', 'Client data find For binrange ', '');
                                                    cfunction.fnPrintLogs('debug', 'Client data find For binrange = ' + vBin, JSON.stringify(FindResult));

                                                    if (FindResult.length > 0) {
                                                        let clientData = {};
                                                        FindResult.forEach(function (param) {
                                                            if (param.LevelTypeId == 1 || param.LevelTypeId == 0) {
                                                                clientData = param;
                                                            }
                                                        });
                                                        if (clientData.CAVVKeyGen != undefined && clientData.CAVVKeyGen != null && clientData.CAVVKeyGen != "") {
                                                            vReqData.CAVVKeyGen = clientData.CAVVKeyGen;
                                                        }


                                                        let IssuerObject = cfunction.getIssuerKeys(clientData, vBin);
                                                        vReqData.IssuerKeys = IssuerObject != undefined ? IssuerObject : {};

                                                        vReqData.transStatus = "Y";
                                                        vReqData.authenticationType = "04"
                                                        vReqData.interactionCounter = "01";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    }
                                                    else {
                                                        cfunction.fnPrintLogs('error', 'Client data not fond For binrange = ', '');
                                                        cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                        vReqData.CAVVKeyGen = "";
                                                        vReqData.transStatus = "N";
                                                        vReqData.transStatusReason = "14";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    }

                                                })
                                            } else {
                                                let obj = {
                                                    '{MessageType}': "pOrq",
                                                    '{MessageVersion}': vReqData.messageVersion,
                                                    '{P_MessageVersion}': "1.0.5",
                                                    '{ThreeDSServerTransID}': threeDSServerTransID,
                                                    '{TransID}': ReqUUID,
                                                };
                                                let poReqObj = CardData.DCParam;
                                                for (let key in obj) {
                                                    poReqObj = poReqObj.replace(key, obj[key].toString());
                                                }
                                                poReqObj = JSON.parse(poReqObj);

                                                let time = vReqData.threeDSRequestorDecMaxTime != undefined ? parseInt(vReqData.threeDSRequestorDecMaxTime) : 1
                                                cfunction.pOrq(poReqObj, time * 60 * 1000, CardData.DCUrl, CardData.InstitutionId, CardData.ClientId, function (err, FimeData) {
                                                    if (err) {
                                                        cfunction.fnPrintLogs('info', ' areq pOrq err = ' + err, '');
                                                        cfunction.fnPrintLogs('info', ' request failed ', '');
                                                        vReqData.transStatusReason = "14";
                                                        vReqData.transStatus = "U";
                                                        vReqData.challengeCancel = "03";
                                                        fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                    } else {
                                                        cfunction.fnPrintLogs('debug', ' areq pOrq FimeData = ' + JSON.stringify(FimeData), '');
                                                        if (FimeData.isOobSuccessful || !FimeData.p_isOobSuccessful) {
                                                            let vBin = vReqData.acctNumber;
                                                            vBin = cfunction.getBigInt(vBin);


                                                            cfunction.getClientCard(vBin, function (FindResult) {
                                                                cfunction.fnPrintLogs('info', 'Client data find For binrange ', '');
                                                                cfunction.fnPrintLogs('debug', 'Client data find For binrange = ' + vBin, JSON.stringify(FindResult));

                                                                if (FindResult.length > 0) {
                                                                    let clientData = {};
                                                                    FindResult.forEach(function (param) {
                                                                        if (param.LevelTypeId == 1 || param.LevelTypeId == 0) {
                                                                            clientData = param;
                                                                        }
                                                                    });
                                                                    if (clientData.CAVVKeyGen != undefined && clientData.CAVVKeyGen != null && clientData.CAVVKeyGen != "") {
                                                                        vReqData.CAVVKeyGen = clientData.CAVVKeyGen;
                                                                    }


                                                                    let IssuerObject = cfunction.getIssuerKeys(clientData, vBin);
                                                                    vReqData.IssuerKeys = IssuerObject != undefined ? IssuerObject : {};

                                                                    vReqData.transStatus = "Y";
                                                                    vReqData.authenticationType = "04";
                                                                    vReqData.interactionCounter = "01";
                                                                    fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                                }
                                                                else {
                                                                    cfunction.fnPrintLogs('error', 'Client data not fond For binrange = ', '');
                                                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                                    vReqData.CAVVKeyGen = "";
                                                                    vReqData.transStatus = "N";
                                                                    vReqData.transStatusReason = "14";
                                                                    fnRReqProcessing(vReqData, { data: { authenticationMethod: "10" } });
                                                                }

                                                            })

                                                        }
                                                    }
                                                });
                                            }
                                            function fnRReqProcessing(AReqData, result) {

                                                cfunction.fnPrintLogs('info', ' fnRReqProcessing called for uuid = ' + ReqUUID, "");
                                                cfunction.fnPrintLogs('info', ' fnRReqProcessing called with AReqData = ' + ReqUUID + ' result : ' + JSON.stringify(result), "");

                                                cfunction.fnRReqData(vReqData, AReqData, result, function (err, RReqData) {
                                                    if (err) {
                                                        cfunction.fnPrintLogs('error', ' fnRReqProcessing err called for uuid = ' + ReqUUID, err);
                                                    } else {
                                                        cfunction.fnPrintLogs('debugg', ' fnRReqProcessing called for uuid = ' + ReqUUID, JSON.stringify(RReqData));
                                                        RReqData.deviceChannel = vReqData.deviceChannel;
                                                        RReqData.purchaseAmount = vReqData.purchaseAmount;
                                                        RReqData.authenticationType = AReqData.authenticationType;
                                                        RReqData.interactionCounter = AReqData.interactionCounter;
                                                        let vRReqInsert = {};
                                                        vRReqInsert.AcsTransID = ReqUUID;
                                                        vRReqInsert.threeDSServerTransID = threeDSServerTransID;
                                                        vRReqInsert.Host = system.hostname();
                                                        vRReqInsert.Datetime = new Date();
                                                        vRReqInsert.Status = "Done";
                                                        vRReqInsert.ApiName = "RReq";
                                                        vRReqInsert.ApiData = RReqData;
                                                        vRReqInsert.Type = "Request";
                                                        vRReqInsert.ErrorCode = "0000";
                                                        vRReqInsert.InstitutionId = vReqData.InstitutionId;
                                                        vRReqInsert.ClientId = vReqData.ClientId;
                                                        vRReqInsert.DirectoryServer = vReqData.DirectoryServer;
                                                        vRReqInsert.DsId = vReqData.DsId;
                                                        vRReqInsert.Originator = vReqData.serverUrl;
                                                        vRReqInsert.CountryCode = vReqData.CountryCode;
                                                        let av;
                                                        if (vRReqInsert.ApiName != null && vRReqInsert.Status != null) {
                                                            let Rmatrics = {};
                                                            Rmatrics.ApiName = vRReqInsert.ApiName;
                                                            Rmatrics.Status = vRReqInsert.Status;
                                                            cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRReqInsert.ApiName + " " + vRReqInsert.Status + JSON.stringify(Rmatrics), '');
                                                        }

                                                        if (vRReqInsert.ApiData != undefined && vRReqInsert.ApiData.authenticationValue != undefined && vAResInsert.ApiData.authenticationValue != "") {
                                                            av = vRReqInsert.ApiData.authenticationValue;
                                                            vRReqInsert.ApiData.authenticationValue = cfunction.Encryption(av);
                                                        }

                                                        insertOne(vRReqInsert, ApiRecordsCollection, handleRReqAPIInsertSuc, handleRReqAPIInsertErr, [av]);

                                                        function handleRReqAPIInsertSuc(insertResult, vData) {
                                                            cfunction.fnPrintLogs('info', 'RReq Request Inserted For uuid = ' + ReqUUID, '');
                                                            cfunction.fnPrintLogs('debug', 'RReq Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                                                            cfunction.fnPrintLogs('debug', 'RReq Request aditional data For uuid = ' + ReqUUID, vData);

                                                            vRReqInsert.ApiData.authenticationValue = vData;
                                                            RReqData.authenticationValue = vData;
                                                            cfunction.fnRequestEncryption(RReqData, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (encData) {
                                                                if (encData.success) {
                                                                    cfunction.fnSendRReqtoDs(AReqData.dsURL, AReqData.DirectoryServer, encData.data, function (cbData) {
                                                                        if (cbData.success) {

                                                                            cfunction.fnRequestDecryption(vReqData.serverUrl, cbData.data, ReqUUID, req.headers.encStatus, function (cbDataD) {
                                                                                if (cbDataD.data) {
                                                                                    cbDataD.data.deviceChannel = vReqData.deviceChannel;
                                                                                    cbDataD.data.purchaseAmount = vReqData.purchaseAmount;
                                                                                    cbDataD.data.purchaseCurrency = vReqData.purchaseCurrency;
                                                                                }
                                                                                let vRResInsert = {};
                                                                                vRResInsert.AcsTransID = ReqUUID;
                                                                                vRResInsert.threeDSServerTransID = threeDSServerTransID;
                                                                                vRResInsert.Host = system.hostname();
                                                                                vRResInsert.Datetime = new Date();
                                                                                vRResInsert.Status = "Done";
                                                                                vRResInsert.ApiName = "RRes";
                                                                                vRResInsert.ApiData = cbDataD.data;
                                                                                vRResInsert.Type = "Response";
                                                                                vRResInsert.ErrorCode = "0000";
                                                                                vRResInsert.InstitutionId = vReqData.InstitutionId;
                                                                                vRResInsert.ClientId = vReqData.ClientId;
                                                                                vRResInsert.DirectoryServer = vReqData.DirectoryServer;
                                                                                vRResInsert.DsId = vReqData.DsId;
                                                                                vRResInsert.Originator = vReqData.serverUrl;
                                                                                vRResInsert.CountryCode = vReqData.CountryCode;
                                                                                if (vRResInsert.ApiName != null && vRResInsert.Status != null) {
                                                                                    let Rmatrics = {};
                                                                                    Rmatrics.ApiName = vRResInsert.ApiName;
                                                                                    Rmatrics.Status = vRResInsert.Status;
                                                                                    cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRResInsert.ApiName + " " + vRResInsert.Status + JSON.stringify(Rmatrics), '');
                                                                                }
                                                                                insertOne(vRResInsert, ApiRecordsCollection, handleRResAPIInsertSuc2, handleRResAPIInsertErr2);
                                                                                function handleRResAPIInsertSuc2(insertResult) {

                                                                                    cfunction.fnPrintLogs('info', 'RRes Request Inserted For uuid = ' + ReqUUID, '');
                                                                                    cfunction.fnPrintLogs('debug', 'RRes Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));

                                                                                    let rresVal = cfunction.fnRresValidation(cbDataD.data, RReqData);

                                                                                    cfunction.fnPrintLogs('debug', 'rresVal response = ' + ReqUUID, JSON.stringify(rresVal));

                                                                                    vReqData.challengeCompletionInd = "Y";
                                                                                    if (!rresVal.RequestStatus) {
                                                                                        vReqData.transStatus = "N";
                                                                                        let errorCode = rresVal.errCode != undefined ? rresVal.errCode : 17;
                                                                                        if (errorCode == 5) {
                                                                                            vReqData.errorCode = rresVal.errorCode;
                                                                                            vReqData.errorDescription = rresVal.errorDescription;
                                                                                            vReqData.errorDetail = rresVal.errorDetail;
                                                                                        }
                                                                                        let errRes = cfunction.fnErrorResponse(vReqData, errorCode);;
                                                                                        errRes.errorMessageType = "RRes";
                                                                                        fnSendRResErrorMSGToDS1(errRes);
                                                                                        cfunction.fnPrintLogs('debug', ' error request from ds for rreq ' + JSON.stringify(errRes), '');
                                                                                        cfunction.fnPrintLogs('debug', ' request failed ', ReqUUID);
                                                                                    }
                                                                                }

                                                                                function handleRResAPIInsertErr2(insertErr) {
                                                                                    cfunction.fnPrintLogs('error', ' handleRResAPIInsertErr2 For uuid = ' + ReqUUID, insertErr);
                                                                                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                                                    if (!res._headerSent) {
                                                                                        cfunction.fnPrintLogs('debug', ' handleRResAPIInsertErr2 res sent For uuid = ' + JSON.stringify(errRes), '');
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                        else {
                                                                            cfunction.fnPrintLogs('error', ' RReq fail to Response For uuid = ' + ReqUUID + " ,Error= " + JSON.stringify(cbData.data), "");
                                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                                            let verrcode = 17;
                                                                            let vReturnErroCode = (typeof cbData.data === 'string') ? cbData.data : cbData.data.code;
                                                                            cfunction.fnPrintLogs('error', ' RReq fail to Response For uuid = ' + ReqUUID + " ,Error= " + vReturnErroCode, "");

                                                                            if (vReturnErroCode == "ESOCKETTIMEDOUT" || vReturnErroCode == "ETIMEDOUT") {
                                                                                verrcode = 16;
                                                                            }
                                                                            let errRes = cfunction.fnErrorResponse(vReqData, verrcode);
                                                                            let vRResInsert = {};
                                                                            vRResInsert.AcsTransID = ReqUUID;
                                                                            vRResInsert.threeDSServerTransID = threeDSServerTransID;
                                                                            vRResInsert.Host = system.hostname();
                                                                            vRResInsert.Datetime = new Date();
                                                                            vRResInsert.Status = "Error";
                                                                            vRResInsert.ApiName = "RRes";
                                                                            vRResInsert.ApiData = cbData.data;
                                                                            vRResInsert.Type = "Response";
                                                                            vRResInsert.ErrorCode = errRes.errorCode;
                                                                            vRResInsert.InstitutionId = vReqData.InstitutionId;
                                                                            vRResInsert.ClientId = vReqData.ClientId;
                                                                            vRResInsert.DirectoryServer = vReqData.DirectoryServer;
                                                                            vRResInsert.Originator = vReqData.serverUrl;
                                                                            vRResInsert.DsId = vReqData.DsId;
                                                                            vRResInsert.CountryCode = vReqData.CountryCode;
                                                                            if (vRResInsert.ApiName != null && vRResInsert.Status != null) {
                                                                                let Rmatrics = {};
                                                                                Rmatrics.ApiName = vRResInsert.ApiName;
                                                                                Rmatrics.Status = vRResInsert.Status;
                                                                                cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vRResInsert.ApiName + " " + vRResInsert.Status + JSON.stringify(Rmatrics), '');
                                                                            }
                                                                            insertOne(vRResInsert, ApiRecordsCollection, handleRResAPIInsertSuc3, handleRResAPIInsertErr3);
                                                                            function handleRResAPIInsertSuc3(insertResult) {
                                                                                cfunction.fnPrintLogs('info', 'RRes Fail Inserted For uuid = ' + ReqUUID, '');
                                                                                cfunction.fnPrintLogs('debug', 'RRes Fail  Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                                                                                fnSendRResErrorMSGToDS1(errRes);
                                                                            }

                                                                            function handleRResAPIInsertErr3(insertErr) {
                                                                                cfunction.fnPrintLogs('error', ' handleRResAPIInsertErr3 RRes Fail  Inserted For uuid = ' + ReqUUID, insertErr);
                                                                                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                                                if (!res._headerSent) {
                                                                                    cfunction.fnPrintLogs('debug', ' handleRResAPIInsertErr3 RRes Fail  Inserted sent For uuid = ' + JSON.stringify(errRes), '');
                                                                                }
                                                                            }

                                                                        }
                                                                    });
                                                                }
                                                            });
                                                        }

                                                        function handleRReqAPIInsertErr(insertErr) {
                                                            cfunction.fnPrintLogs('error', ' handleRReqAPIInsertErr For uuid = ' + ReqUUID, insertErr);
                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                                                            vRReqInsert.ApiData.authenticationValue = av;
                                                            if (!res._headerSent) {
                                                                cfunction.fnSessionUpdate(ReqUUID, sessionData, sstatus, function (err, SessionResResult) {
                                                                    let errRes = cfunction.fnErrorResponse(vReqData, 17);
                                                                    cfunction.fnPrintLogs('debug', ' handleRReqAPIInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                                                                    cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                                                                        cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                                                                        res.send(cbData.data).end();
                                                                    });
                                                                });
                                                            }
                                                        }
                                                    }
                                                });

                                                function fnSendRResErrorMSGToDS1(RResData) {
                                                    cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS1 called for uuid = ' + ReqUUID, "");
                                                    cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS1 called with RResData = ' + ReqUUID + ' result : ' + JSON.stringify(RResData), "");

                                                    cfunction.fnSendRReqtoDs(AReqData.dsURL, AReqData.DirectoryServer, RResData, function (cbData) {
                                                        if (cbData.success) {
                                                            cfunction.fnPrintLogs('info', ' fnSendRResErrorMSGToDS1 Decription Response for RResData = ' + ReqUUID + ' RRespData : ' + JSON.stringify(cbData), "");
                                                        }
                                                        else {
                                                            cfunction.fnPrintLogs('error', 'fnSendRResErrorMSGToDS1 RRes fail to Response For uuid = ' + ReqUUID + " ,Error= " + JSON.stringify(cbData), "");
                                                            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                                                        }
                                                    })
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }

                function handleAReqUpdateErr(ferr) {
                    cfunction.fnPrintLogs('error', ' handleAReqUpdateErr For uuid = ' + ReqUUID, ferr);
                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                    let errRes = cfunction.fnErrorResponse(vReqData, 17);
                    if (!res._headerSent) {
                        cfunction.fnPrintLogs('debug', 'handleAReqUpdateErr res sent for uuid = ' + ReqUUID, JSON.stringify(errRes));
                        cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                            cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                            res.send(cbData.data).end();
                        });
                    }
                }
            }


        });
    } else {
        cfunction.fnPrintLogs('info', 'AReq Request header is not in valid format, request failed here For uuid = ' + ReqUUID, '');
        cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

        let vQuery = {};
        vQuery.AcsTransID = ReqUUID;
        vQuery.Host = system.hostname();
        vQuery.Datetime = new Date();
        vQuery.Status = "Error";
        vQuery.ApiName = "AReq";
        vQuery.ApiData = req.body;
        vQuery.Type = "Request";
        vQuery.ErrorCode = "203";

        if (vQuery.ApiName != null && vQuery.Status != null) {
            let Amatrics = {};
            Amatrics.ApiName = vQuery.ApiName;
            Amatrics.Status = vQuery.Status;
            cfunction.fnPrintLogs('info', 'Data for Prometheus ' + vQuery.ApiName + " " + vQuery.Status + JSON.stringify(Amatrics), '');
        }
        insertOne(vQuery, ApiRecordsCollection, handleAPIInsertSuc1, handleAPIInsertErr1);
        function handleAPIInsertSuc1(insertResult) {
            cfunction.fnPrintLogs('info', 'AReq Request Inserted For uuid = ' + ReqUUID, '');
            cfunction.fnPrintLogs('debug', 'AReq Request Inserted For uuid = ' + ReqUUID, JSON.stringify(insertResult));
            cfunction.fnPrintLogs('info', 'AReq validation failed For uuid = ' + ReqUUID, '');

            vReqData.messageType = "AReq";
            let vAResInsert = {};
            vAResInsert.AcsTransID = ReqUUID;
            vAResInsert.threeDSServerTransID = threeDSServerTransID;
            vAResInsert.Host = system.hostname();
            vAResInsert.Datetime = new Date();
            vAResInsert.Status = "Error";
            vAResInsert.ApiName = "ARes";
            vAResInsert.ApiData = req.body;
            vAResInsert.Type = "Response";
            vAResInsert.ErrorCode = "203";

            insertOne(vAResInsert, ApiRecordsCollection, handleAResInsertSucc, handleAResInsertErr);

            function handleAResInsertErr(insertErr) {
                cfunction.fnPrintLogs('error', ' handleAResInsertErr For uuid = ' + ReqUUID, insertErr);
                cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);

                let errRes = cfunction.fnErrorResponse(vReqData, 17);
                if (!res._headerSent) {
                    cfunction.fnPrintLogs('debug', ' handleAResInsertErr res sent For uuid = ' + JSON.stringify(errRes), '');
                    cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                        cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                        res.send(cbData.data).end();
                    });
                }
            }

            function handleAResInsertSucc(insertResult) {
                cfunction.fnPrintLogs('info', ' handleAResInsertSucc For uuid = ' + ReqUUID, '');
                cfunction.fnPrintLogs('debug', ' handleAResInsertSucc For uuid = ' + ReqUUID, JSON.stringify(insertResult));

                let errRes = cfunction.fnErrorResponse(vReqData, 7);
                if (!res._headerSent) {
                    cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                        res.status(415).send(cbData.data).end();
                    });
                }
            }
        }

        function handleAPIInsertErr1(insertErr) {
            cfunction.fnPrintLogs('error', ' handleAPIInsertErr1 For uuid = ' + ReqUUID, insertErr);
            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
            let errRes = cfunction.fnErrorResponse(vReqData, 17);
            if (!res._headerSent) {
                cfunction.fnPrintLogs('debug', ' handleAPIInsertErr1 res sent For uuid = ' + JSON.stringify(errRes), '');
                cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                    cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                    res.send(cbData.data).end();
                });
            }
        }
    }
    function fnApiTimeout() {
        cfunction.fnPrintLogs('info', ' fnApiTimeout For uuid = ' + ReqUUID, '');
        if (!res._headerSent && InitiateInsert) {
            InitiateInsert = false;
            cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
            let errRes = cfunction.fnErrorResponse(vReqData, 17);
            errRes.transStatusReason = "14";
            cfunction.fnPrintLogs('debug', 'fnApiTimeout res sent for uuid = ' + ReqUUID, JSON.stringify(errRes));
            cfunction.fnRequestEncryption(errRes, ReqUUID, req.headers.encStatus, vReqData.serverUrl, req.headers, function (cbData) {
                cfunction.fnPrintLogs('warn', 'AReq time (seconds, nanoseconds) = ' + process.hrtime(hrtimeTotal), '');
                res.send(cbData.data).end();

                let AReqFind = { AcsTransID: ReqUUID, ApiName: "AReq" };
                let AReqUpdateData = { $set: { "Status": "Timeout", "InstitutionId": vReqData.InstitutionId, "ClientId": vReqData.ClientId, "DirectoryServer": vReqData.DirectoryServer, "DsId": vReqData.DsId, "Originator": vReqData.serverUrl, "CountryCode": vReqData.CountryCode, "ErrorCode": "500", "ApiData.transStatus": "N", "ApiData.transStatusReason": "14" } };

                cfunction.fnPrintLogs('info', 'Data for Prometheus AReq New' + JSON.stringify(AReqFind), '');

                updateOne(AReqFind, AReqUpdateData, ApiRecordsCollection, handleAReqUpdateSucc, handleAReqUpdateErr);

                function handleAReqUpdateSucc(fresult) {
                    cfunction.fnPrintLogs('info', ' function handleAReqUpdateSucc called ', '');
                    cfunction.fnPrintLogs('debug', ' function handleAReqUpdateSucc called with fresult : ' + JSON.stringify(fresult), '');
                }

                function handleAReqUpdateErr(err) {
                    cfunction.fnPrintLogs('info', ' function handleAReqUpdateErr called ', '');
                    cfunction.fnPrintLogs('error', ' request failed here : ' + err.stack, '');
                }

                let vAResInsert = {};
                vAResInsert.AcsTransID = ReqUUID;
                vAResInsert.threeDSServerTransID = threeDSServerTransID;
                vAResInsert.Host = system.hostname();
                vAResInsert.Datetime = new Date();
                vAResInsert.Status = "Timeout";
                vAResInsert.ApiName = "ARes";
                vAResInsert.ApiData = errRes;
                vAResInsert.Type = "Response";
                vAResInsert.ErrorCode = "500";

                vAResInsert.InstitutionId = vReqData.InstitutionId;
                vAResInsert.ClientId = vReqData.ClientId;
                vAResInsert.DirectoryServer = vReqData.DirectoryServer;
                vAResInsert.Originator = vReqData.serverUrl
                vAResInsert.DsId = vReqData.DsId;
                vAResInsert.CountryCode = vReqData.CountryCode;

                insertOne(vAResInsert, ApiRecordsCollection, handleAResInsertSucc, handleAResInsertErr);

                function handleAResInsertErr(insertErr) {
                    cfunction.fnPrintLogs('error', ' handleAResInsertErr For uuid = ' + ReqUUID, insertErr);
                    cfunction.fnPrintLogs('error', 'request failed here ', ReqUUID);
                }

                function handleAResInsertSucc(insertResult) {
                    cfunction.fnPrintLogs('info', ' handleAResInsertSucc For uuid = ' + ReqUUID, '');
                    cfunction.fnPrintLogs('debug', ' handleAResInsertSucc For uuid = ' + ReqUUID, JSON.stringify(insertResult));
                }
            });
        }
    };

    function insertVelocity(CardData) {
        let tmpAcctNumber = cfunction.Encryption(vReqData.acctNumber.toString().trim());
        let vcard = cfunction.EncryptionOld(vReqData.acctNumber.toString().trim());
        let merchantName = vReqData.merchantName;
        let tempInstitutionId = CardData.InstitutionId;
        let tempClientId = CardData.ClientId != undefined && CardData.ClientId != null ? CardData.ClientId : "";
        let findOrgTxns = { CardNumber: { $in: [tmpAcctNumber, vcard] } };
        let addRuleDetails = { $inc: { recuringTransaction: 1, perDayTransCount: 1, perDayTransAmt: parseFloat(vReqData.purchaseAmount) }, $set: { InstitutionId: tempInstitutionId, ClientId: tempClientId } };

        //updateOne(findOrgTxns, addRuleDetails, "TransactionRule",{ upsert: true }, handleFindOneRuleSuccess, handleFindOneRuleErr);
        //updateOne(findOrgTxns, addRuleDetails,TransactionRule, options,handleFindOneRuleSuccess,handleFindOneRuleErr);
        db.collection("TransactionRule").updateOne(findOrgTxns, addRuleDetails, { upsert: true });
        // function handleFindOneRuleSuccess(res){
        //     console.log(res);
        // }
        // function handleFindOneRuleErr(err){
        //     console.log(err);
        // }
    }

    function updateVelocity(CardData) {
        let tmpAcctNumber = cfunction.Encryption(vReqData.acctNumber.toString().trim());
        let vcard = cfunction.EncryptionOld(vReqData.acctNumber.toString().trim());
        let merchantName = vReqData.merchantName;
        let tempInstitutionId = CardData.InstitutionId;
        let tempClientId = CardData.ClientId != undefined && CardData.ClientId != null ? CardData.ClientId : "";
        let findOrgTxns = { CardNumber: { $in: [tmpAcctNumber, vcard] } }
        // {
        //     $or: [
        //         { CardNumber: { $in: [tmpAcctNumber, vcard] } },
        //         { merchantName: merchantName }
        //     ]
        // };
        let addRuleDetails = { $set: { "recuringTransaction": 0, InstitutionId: tempInstitutionId, ClientId: tempClientId }, $inc: { perDayTransCount: 1, perDayTransAmt: parseFloat(vReqData.purchaseAmount) } };
        //let addRuleDetails = { $set: { "recuringTransaction": 0} };
        updateOneWithParam(findOrgTxns, addRuleDetails, { upsert: true }, TransactionRule, handleFindOneRuleSuccess, handleFindOneRuleErr);
        function handleFindOneRuleSuccess(res) {
            console.log(res);
        }
        function handleFindOneRuleErr(err) {
            console.log(err);
        }
    }

    
});
module.exports = router;