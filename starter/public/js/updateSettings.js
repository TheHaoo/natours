// update data function

import { showAlert } from "./alerts"

// Type is either 'password' or 'data'
export const updateSettings = async (data, type) => {
  try {
    const url = 
      type === 'Password'
        ? 'http://127.0.0.1:3000/api/v1/users/updateMyPassword'
        : 'http://127.0.0.1:3000/api/v1/users/updateMe'

    const res = await axios({
      method: 'PATCH',
      url,
      data
    })

    if (res.data.status === 'success') {
      showAlert('success', `${type} updated successfully!`)
      window.setTimeout(() => location.assign('/'), 500);
    }
  } catch (err) {
    showAlert('error', err.response.data.message)
  }
}