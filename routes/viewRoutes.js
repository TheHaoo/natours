const express = require('express');
const viewsController = require('../controllers/viewsController')
const authController = require('../controllers/authController')

const router = express.Router()

router.get('/signup', viewsController.signup)
router.get('/wait-confirm', viewsController.waitConfirm)
router.get('/forgot-password', viewsController.forgotPassword)
router.get('/reset-password/:token', viewsController.resetPassword)

router.get('/', authController.isLoggedIn, viewsController.getOverview)
router.get('/tour/:slug', authController.isLoggedIn, viewsController.getTour)
router.get('/login', authController.isLoggedIn, viewsController.getLoginForm)

router.get('/me', authController.protect, viewsController.getAccount)
router.post('/submit-user-data', authController.protect, viewsController.updateUserData)

module.exports = router