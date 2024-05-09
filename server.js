const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncaughtException', err => {
    console.log(err.name, err.message);
    console.log('UNCAUGHT EXCEPTION! Shutting down')
    // 0 stands for success, 1 stands for uncaught exception
    process.exit(1);
}) 

dotenv.config({path: './config.env'});

const app = require('./app');

console.log(process.env.NODE_ENV)

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose.connect(DB, {
    autoCreate: true,
    autoIndex: true,
}).then(() => console.log('DB Connection successful!'));

const port = 3000;
const server = app.listen(port, () => {
    console.log(`App running on port ${port}...`);
});

process.on('unhandledRejection', err => {
    console.log(err.name, err.message);
    console.log('UNHANDLER REJECTION! Shutting down')
    // 0 stands for success, 1 stands for uncaught exception
    server.close(() => {
        process.exit(1);
    })
})