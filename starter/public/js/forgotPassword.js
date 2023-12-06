import { showAlert } from './alerts.js'

export const forgotPassword = async (email) => {
  try {
    const res = await axios({
      method: 'POST',
      url: 'http://127.0.0.1:3000/api/v1/users/forgotPassword',
      data: {
        email
      }
    })

    console.log(res.data)

    if (res.data.status === 'success') {
      showAlert('success', 'Email sent successfully!')
      window.setTimeout(() => {
        location.assign('/wait-confirm')
      }, 500)
    }
  } catch (err) {
    showAlert('error', 'Can not find this email!')
  }
}