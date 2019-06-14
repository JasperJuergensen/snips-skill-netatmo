#!/usr/bin/env python3

from hermes_python.hermes import Hermes
from hermes_python.ffi.utils import MqttOptions

import requests
from oauthlib.oauth2 import LegacyApplicationClient, TokenExpiredError
from requests_oauthlib import OAuth2Session

import configparser
import toml

import datetime

import mqtthandler
import logging

station = None

MQTT_BROKER_ADDRESS = "localhost:1883"
MQTT_USERNAME = None
MQTT_PASSWORD = None

# get snips config
snips_config = toml.load('/etc/snips.toml')
if 'mqtt' in snips_config['snips-common'].keys():
    MQTT_BROKER_ADDRESS = snips_config['snips-common']['mqtt']
if 'mqtt_username' in snips_config['snips-common'].keys():
    MQTT_USERNAME = snips_config['snips-common']['mqtt_username']
if 'mqtt_password' in snips_config['snips-common'].keys():
    MQTT_PASSWORD = snips_config['snips-common']['mqtt_password']

# get app specific config
config = configparser.ConfigParser()
config.read("config.cfg")

# set up logging
mqtthdlr = mqtthandler.MQTTHandler(MQTT_BROKER_ADDRESS.split(':')[0], config.get('Logging', 'topic'))
mqtthdlr.setLevel(logging.DEBUG)
if MQTT_USERNAME and MQTT_PASSWORD:
    mqtthdlr.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

logger = logging.getLogger()
logger.addHandler(mqtthdlr)
logger.setLevel(config.get('Logging', 'level'))


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
        self.last_request = None
        self.cached_weather_data = None

    def get_access_token(self):
        oauth = OAuth2Session(client=LegacyApplicationClient(client_id=self.client_id))
        token = oauth.fetch_token(token_url=self.auth_url,
            username=self.username, password=self.password, client_id=self.client_id, 
            client_secret=self.client_secret, scope=self.scope)
        self.password = None
        return token

    def token_saver(self, token):
        self.token = token

    @property
    def weather_data(self):

        if self.cached_weather_data is not None and \
        self.last_request is not None and \
        (datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(self.last_request)) < datetime.timedelta(minutes=3):
            logger.debug('Read weather data from cache')
            return self.cached_weather_data

        params = dict(device_id=self.device_id)

        if datetime.datetime.fromtimestamp(self.token['expires_at']) < datetime.datetime.now():
            logger.debug('Token expired')
            self.token['expires_in'] = -30
            self.token['expire_in'] = -30

        try:
            logger.debug('Request weather data from API')
            client = OAuth2Session(self.client_id, token=self.token, 
                auto_refresh_url=self.refresh_url, 
                auto_refresh_kwargs={'client_id': self.client_id, 'client_secret': self.client_secret}, 
                token_updater=self.token_saver)
            response = client.get(self.weather_data_url, params=params)
        except Exception as e:
            logger.warning('Requesting data from API returns error: {}'.format(repr(e)))
            raise WeatherParserException('Die API ist aktuell nicht erreichbar.')

        if response.status_code != requests.codes.ok:
            logger.info('The API returned HTTP {}'.format(response_data.status_code))
            raise WeatherParserException('Die API hat einen HTTP Status {} zurückgegeben.'.format(response.status_code))

        response_data = response.json()

        if response_data['status'] != 'ok':
            logger.info('The API returned "{}" as status'.format(response_data['status']))
            raise WeatherParserException('Die API hat nicht den Status ok zurückgegeben.')

        data = self.parse_response(response_data['body'])
        self.cached_weather_data = data
        self.last_request = response_data['body']['devices'][0]['dashboard_data']['time_utc']
        logger.debug('Updated cache time to {}'.format(str(self.last_request)))

        return data

    def parse_response(self, data):
        weather_data = None
        if len(data['devices']) != 1:
            logger.warning('Found {} devices'.format(len(data['devices'])))
            raise WeatherParserException('Es wurde mehr als ein oder gar kein Gerät gefunden.')

        device = data['devices'][0]

        for module in device['modules']:
            if module['type'] == 'NAModule1':  # Outdoor module
                weather_data = module['dashboard_data']
        if weather_data is None:
            logger.warning('Outdoor module not found')
            raise WeatherParserException('Es wurde kein Außenmodul gefunden.')

        weather_data['Pressure'] = device['dashboard_data']['Pressure']

        return weather_data

    @property
    def temperature(self):
        return self.weather_data['Temperature']

    @property
    def humidity(self):
        return self.weather_data['Humidity']

    @property
    def pressure(self):
        return self.weather_data['Pressure']


def weatherOutdoor(hermes, intentMessage):
    global station
    weather_type = intentMessage.slots.weather_type.first().value
    try:
        if weather_type == 'Temperatur':
            text = 'Die aktuelle Außentemperatur beträgt {} Grad Celsius.'.format(str(station.temperature).replace('.', ','))
        elif weather_type == 'Luftfeuchtigkeit':
            text = 'Die aktuelle Luftfeuchtigkeit liegt bei {} Prozent.'.format(str(station.humidity).replace('.', ','))
        elif weather_type == 'Luftdruck':
            text = 'Der Luftdruck beträgt aktuell {} Millibar'.format(str(station.pressure).replace('.', ','))
        else:
            text = 'Ich habe dich leider nicht verstanden'
            logger.info('Request could not be understood')
    except WeatherParserException as e:
        text = e.message
    except Exception as e:
        logger.error('An exception occured: {}'.format(repr(e)))
        text = 'Es ist leider ein Fehler aufgetreten.'
    hermes.publish_end_session(intentMessage.session_id, text)


def main():
    mqtt_opts = MqttOptions(username=MQTT_USERNAME, password=MQTT_PASSWORD, broker_address=MQTT_BROKER_ADDRESS)

    global station
    station = NetatmoWeatherStation(config)

    logger.debug('Start listening on {}'.format(MQTT_BROKER_ADDRESS))
    with Hermes(mqtt_opts) as h:
        h.subscribe_intent("JasperJuergensen:OutdoorWeather", weatherOutdoor).loop_forever()


if __name__ == "__main__":  
    main()
