from hermes_python.hermes import Hermes

import requests
from oauthlib.oauth2 import LegacyApplicationClient, TokenExpiredError
from requests_oauthlib import OAuth2Session

import configparser

station = None


class WeatherParserException(Exception):
    def __init__(self, message):
        super().__init__(message)


class NetatmoWeatherStation:

    def __init__(self, api_config):
        self.device_id = api_config.get('NetatmoAccount', 'device_id')
        self.client_id = api_config.get('NetatmoAccount', 'client_id')
        self.client_secret = api_config.get('NetatmoAccount', 'client_secret')
        self.username = api_config.get('NetatmoAccount', 'username')
        self.password = api_config.get('NetatmoAccount', 'password')
        self.scope = 'read_station'
        self.auth_url = api_config.get('NetatmoAccount', 'auth_url')
        self.weather_data_url = api_config.get('NetatmoAccount', 'weather_data_url')
        self.refresh_url = api_config.get('NetatmoAccount', 'refresh_url')
        self.token = self.get_access_token()

    def get_access_token(self):
        oauth = OAuth2Session(client=LegacyApplicationClient(client_id=self.client_id))
        token = oauth.fetch_token(token_url=self.auth_url,
            username=self.username, password=self.password, client_id=self.client_id, 
            client_secret=self.client_secret, scope=self.scope)
        return token

    @property
    def weather_data(self):
        params = dict(device_id=self.device_id)

        try:
            client = OAuth2Session(self.client_id, token=self.token)
            response = client.get(self.weather_data_url, params=params)
        except TokenExpiredError as e:
            self.token = client.refresh_token(self.refresh_url, grant_type='refresh_token')
            client = OAuth2Session(self.client_id, token=self.token)
            response = client.get(self.weather_data_url, params=params)

        if response.status_code != requests.codes.ok:
            raise WeatherParserException('Die API hat einen HTTP Status {} zurückgegeben.'.format(response.status_code))

        response_data = response.json()

        if response_data['status'] != 'ok':
            raise WeatherParserException('Die API hat nicht den Status ok zurückgegeben.')

        data = self.parse_response(response_data['body'])

        return data

    def parse_response(self, data):
        if len(data['devices']) != 1:
            raise WeatherParserException('Es wurde mehr als ein oder gar kein Gerät gefunden.')

        device = data['devices'][0]

        for module in device['modules']:
            if module['type'] == 'NAModule1':  # Outdoor module
                return module['dashboard_data']

        raise WeatherParserException('Es wurde kein Außenmodul gefunden.')

    @property
    def temperature(self):
        return self.weather_data['Temperature']

    @property
    def humidity(self):
        return self.weather_data['Humidity']


def weatherOutdoor(hermes, intentMessage):
    global station
    weather_type = intentMessage.slots.weather_type.first()
    try:
        if weather_type == 'Temperatur':
            text = 'Die Außentemperatur beträgt {} Grad Celsius.'.format(station.temperature)
        elif weather_type == 'Luftfeuchtigkeit':
            text = 'Die Luftfeuchtigkeit liegt bei {} Prozent.'.format(station.humidity)
        else:
            text = 'Ich habe dich leider nicht verstanden'
    except WeatherParserException as e:
        text = e.message
    hermes.publish_end_session(intentMessage.session_id, text)


def main():
    config = configparser.ConfigParser()
    config.read("config.cfg")

    MQTT_ADDR = "{}:{}".format(config.get('MQTT', 'ip'), str(config.get('MQTT', 'port')))

    global station
    station = NetatmoWeatherStation(config)

    with Hermes(MQTT_ADDR) as h:
        h.subscribe_intent("JasperJuergensen:WeatherOutdoor", weatherOutdoor).loop_forever()


if __name__ == "__main__":  
    main()