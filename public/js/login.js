/* eslint-disable*/
import { showAlert } from "./alerts"

// const instance = axios.create({
//   baseURL: process.env.NODE_ENV === 'production' ? process.env.BASE_URL : 'http://127.0.0.1:3000/',
// })

export const login = async (email, password) => {
  try {
    const res = await axios({
      method: 'POST',
      url: 'http://127.0.0.1:3000/api/v1/users/login',
      data: {
        email,
        password
      }
    })

    if (res.data.status === 'success') {
      showAlert('success', 'Logged in successfully!')
      window.setTimeout(() => {
        location.assign('/')
      }, 1000)
    }

  } catch (err) {
    showAlert('error', err.response.data.message)
  }  
}

export const logout = async () => {
  try {
    const res = await axios({
      method: 'GET',
      url: 'http://127.0.0.1:3000/api/v1/users/logout'
    })
    // if (res.data.status = 'success') location.reload(true)
    if (res.data.status = 'success') 
      window.setTimeout(() => {
        location.assign('/')
      }, 1000)
  } catch (err) {
    showAlert('error', 'Error logging out! Try again')
  }
}