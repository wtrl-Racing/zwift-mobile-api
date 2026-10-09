const getAccessToken = require('./getAccessToken')
const Profile = require('./Profile')
const World = require('./World')
const Request = require('./Request')
const Activity = require('./Activity')
const Event = require('./Event')

class ZwiftAccount {
    constructor(username, password, refreshToken = null) {
        this.username = username
        this.password = password

        this.tokenPromise = null

        this.accessToken = null
        this.suppliedRefreshToken = refreshToken;
        this.refreshToken = refreshToken
        this.refreshTokenExpiration = 0
        this.accessTokenExpiration = 0

        this.getAccessToken = this.getAccessToken.bind(this)
        this.getRefreshToken = this.getRefreshToken.bind(this)
    }

    getProfile(playerId) {
        return new Profile(playerId, this.getAccessToken)
    }

    getWorld(worldId) {
        return new World(worldId, this.getAccessToken)
    }

    getActivity(playerId) {
      return new Activity(playerId, this.getAccessToken)
    }

    getEvent() {
        return new Event(this.getAccessToken);
    }

    getRequest() {
        return new Request(this.getAccessToken)
    }

    getAccessToken(resetTokens) {
        if (resetTokens) {
            this.accessToken = null
            this.refreshToken = this.suppliedRefreshToken
            this.refreshTokenExpiration = 0
            this.accessTokenExpiration = 0
            this.tokenPromise = null
        }

        return this.getTokenPromise()
            .then(response => response.data.access_token)
    }

    getRefreshToken() {
        return this.getTokenPromise()
            .then(response => response.data.refresh_token)
    }

    getTokenPromise() {
        const now = Date.now();

        if (
            !this.tokenPromise ||
            (this.accessTokenExpiration &&
                now >= this.accessTokenExpiration)
        ) {
            this.accessTokenExpiration = 0;

            const refreshToken = this.refreshToken;

            const tokenPromise = getAccessToken(
                this.username,
                this.password,
                refreshToken
            )
                .catch(error => {
                    const response = error.response;
                    const details = response && response.data;

                    // Retry with credentials if Zwift rejects the refresh token.
                    if (
                        refreshToken &&
                        details &&
                        details.error === 'invalid_grant' &&
                        this.username &&
                        this.password
                    ) {
                        console.warn(
                            'Zwift refresh token rejected; signing in again.'
                        );

                        this.refreshToken = null;
                        this.refreshTokenExpiration = 0;

                        return getAccessToken(
                            this.username,
                            this.password
                        );
                    }

                    throw error;
                })
                .then(response => {
                    const issuedAt = Date.now();
                    const expiresIn = Math.max(
                        1,
                        Math.min(
                            Number(response.data.expires_in) - 5,
                            30 * 60
                        )
                    );

                    this.accessTokenExpiration =
                        issuedAt + expiresIn * 1000;

                    this.refreshTokenExpiration =
                        issuedAt + Math.max(
                            0,
                            Number(response.data.refresh_expires_in || 0) - 5
                        ) * 1000;

                    this.refreshToken = response.data.refresh_token;
                    this.accessToken = response.data.access_token;

                    return response;
                })
                .catch(error => {
                    // Let the next request try again after a failure.
                    if (this.tokenPromise === tokenPromise) {
                        this.tokenPromise = null;
                        this.accessToken = null;
                        this.accessTokenExpiration = 0;
                    }

                    throw error;
                });

            this.tokenPromise = tokenPromise;
        }

        return this.tokenPromise;
    }
}

module.exports = ZwiftAccount
