const express= require("express");
const { default: mongoose } = require("mongoose");

const userschema= new mongoose.Schema({
    username:{type:String , required:true,unique:true},
    email:{type:String , required:true,unique:true},
    password:{type:String , required:true},
})

const Usermodel = mongoose.model('User', userschema);
module.exports = Usermodel;