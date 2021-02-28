const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

mongoose.connect('mongodb+srv://dhanesh-malviya:dhanesh123@mastercluster-i7cpa.mongodb.net/test?retryWrites=true&w=majority', { useNewUrlParser: true})
  .then( ()=> console.log('database connected...'))
  .catch( err => console.log(err));

const authSchema = new mongoose.Schema({
  email:String,
  password:String,
}, {timestamps: true});

authSchema.plugin(passportLocalMongoose, {usernameField: 'email'});

module.exports = mongoose.model('Auth', authSchema );

