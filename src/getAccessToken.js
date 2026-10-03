const axios = require('axios')
const qs = require('qs')

const SECURE_URL = process.env.ZwiftSecureUrl || 'https://secure.zwift.com/auth/realms/zwift/tokens/access/codes';

module.exports = function getAccessToken(username, password, refreshToken = null) {
    let data
    if (refreshToken) {
        data = {
            "client_id": "Developer Client",
            "refresh_token": refreshToken,
            "grant_type": "refresh_token",
        }
    } else {
        data = {
            "client_id": "Developer Client",
            "username": username,
            "password": password,
            "grant_type": "password",
        }
    }

    return axios.post(SECURE_URL, qs.stringify(data))
        .catch(error => {
            const response = error.response;
            const details = response && response.data;

            console.error('Zwift service-account authentication failed:', {
                url: SECURE_URL,
                status: response && response.status,
                error: details && details.error,
                description: details && details.error_description
            });

            throw error;
        });
}
