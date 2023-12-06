import { showAlert } from "./alerts"

export const bookTour = async tourId => {
  const stripe = Stripe('pk_test_51OJVWDBADLBLEJRn0AWexMHo3YuXHkWPOHa7i5y9nX4dnfymql0obiznCFTLqH0TgDat3JXSyQ3ddlNPis0NWtZX00nBEapsQX')

  try {
    // 1) Get checkout session form API
    const session = await axios (`http://127.0.0.1:3000/api/v1/bookings/checkout-session/${tourId}`)
    console.log(session)
  
    // 2) Create check out form + chanre credit card
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id
    })

  } catch (err) {
    console.log(err)
    showAlert('error', err)
  }
}