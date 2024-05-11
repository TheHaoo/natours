/* eslint-disable import/no-extraneous-dependencies */
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser')

const cors = require('cors');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const bookingRouter = require('./routes/bookingRoutes');
const viewRouter = require('./routes/viewRoutes');

const app = express();

app.set('view engine', 'pug')
app.set('views', path.join(__dirname, 'views'))

// 1) MIDDLEWARE
// Serving static files
app.use(express.static(path.join(__dirname, 'public')));
// Set security HTTP headers
app.use(helmet.contentSecurityPolicy({
  directives: {
    connectSrc: ["'self'", "data:", "blob:", "https://*.stripe.com", "https://*.mapbox.com", "https://*.cloudflare.com", "https://bundle.js:*", "ws://localhost:*"],
    defaultSrc: ["'self'"],
    frameAncestors: ["'self'"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    frameSrc: ["'self'", "data:", "blob:", "https://*.stripe.com", "https://*.mapbox.com", "https://*.cloudflare.com", "https://bundle.js:*", "ws://localhost:*"],
    imgSrc: ["'self'", "data:", "blob:", "https://*.stripe.com", "https://*.mapbox.com", "https://*.cloudflare.com", "https://bundle.js:*", "ws://localhost:*"],
    scriptSrc: ["'self'", "'nonce-rAnd0m'", "data:", "blob:", "https://js.stripe.com", "https://*.mapbox.com", "https://*.cloudflare.com", "https://bundle.js:8828", "ws://localhost:*"],
    styleSrc: ["'self'", "'nonce-rAnd0m'"],
    workerSrc: ["'self'", "'nonce-rAnd0m'", "data:", "blob:", "https://*.stripe.com", "https://*.mapbox.com", "https://*.cloudflare.com", "https://bundle.js:*", "ws://localhost:*"],
  }
}))

app.use(cors(false));

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limits requests from same API
const limiter = rateLimit({
  max: 100, // Brute force: hạn chế hacker thử gửi request 100 mật khẩu để dò mk user
  windowMs: 60 * 60 * 1000,
  message: 'Too many request from this IP, please try again in an hour!'
})
app.use('/api',limiter);

// Body parser, reading data from body into req.bdy
app.use(express.json({limit: '10kb'}));
app.use(express.urlencoded({extended: true, limit: '10kb'}))
app.use(cookieParser())

// Data sanitization against NoSQL query injection
app.use(mongoSanitize()); // Tự động loại bỏ các dollar sign và dot

// Data sanitization against XSS (cross-site scripting)
app.use(xss());

// Prevent parameter pollution
app.use(hpp({
  whitelist: ['duration', 'ratingsAverage', 'ratingsQuantity', 'maxGroupSize', 'difficulty', 'pirce']
}))

// Test middleware
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  // console.log(req.headers)
  next();
})

// 3) ROUTES
app.use('/', viewRouter);
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);
app.use('/api/v1/bookings', bookingRouter);

app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404))
})

app.use(globalErrorHandler)

module.exports = app; 