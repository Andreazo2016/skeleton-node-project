var mongoose = require('mongoose');

module.exports = function(url){
    mongoose.connect(url);

    mongoose.connection.on('connected', function(){
        console.log('Mongoose conectado em ' + url);
    })

    mongoose.connection.on('disconnected', function(){
        console.log('Mongoose desconectado');
    })

    mongoose.connection.on('error', function(err){
        console.log('Mongoose Error' + err);
    })

    process.on('SIGINT', function(){
        mongoose.connection.close(function(){
            console.log('Mongoose encerrado!');
            process.exit(0);
        })
    })
}