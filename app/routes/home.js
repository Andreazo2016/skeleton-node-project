var auth = require('../../config/auth').auth;

module.exports = function(app){
    var controller = app.controllers.home;

    app.get('/', controller.index);
    app.post('/',  auth.authenticate, controller.newItem);
    app.delete('/remove/:id',  auth.authenticate, controller.remove);

    app.post('/login', controller.login);
}