import logging
from logging.handlers import RotatingFileHandler
from sys import argv
from json import loads as read_json
from threading import Thread
from queue import Queue
from time import sleep
from ipaddress import ip_address
from socket import gethostbyname
from socket import gaierror
from socket import error as socket_error
from re import match
from io import BytesIO

from yaml import safe_load as read_yaml
from telebot import TeleBot
from telebot.types import Message
from telebot.types import InlineKeyboardMarkup
from telebot.types import InlineKeyboardButton
from telebot.types import CallbackQuery
from jinja2 import Template
from paramiko import SSHClient
from paramiko import AutoAddPolicy
from paramiko.ssh_exception import SSHException

from classes import Build
from classes import VpnClient
from exceptions import IncorrectConnectionData
from exceptions import IncorrectVpnClientsData

###################################################################################################
#                      Global module VARS
###################################################################################################
CONFIG: dict = {}
SECRET: dict = {}
MESSAGES: dict = {}
CLIENTS: dict[int, VpnClient] = {}
BUILDS = Queue(0)

###################################################################################################
#                      Initialize LOGGER
###################################################################################################
log_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.ERROR
}
logging.basicConfig(
    level=log_levels[argv[4]], 
    format='%(asctime)s [%(levelname)s]: %(message)s')
handler = RotatingFileHandler(
    filename='bot.log', encoding='UTF-8', mode='a',
    maxBytes=5_242_880, backupCount=10)
logger = logging.getLogger()
logger.addHandler(handler)

###################################################################################################
#                      Define UTILS methods
###################################################################################################
def send_message(bot: TeleBot, client: VpnClient,
        message_data: dict, env: dict = {}, markup_row_width: int = 1) -> Message:
    text: str = Template(message_data['text'][client.lang]).render(env)
    parse_mode: str | None = message_data['parse_mode']
    markup: InlineKeyboardMarkup = None
    if 'buttons' in message_data:
        buttons: list = message_data['buttons']
        markup = InlineKeyboardMarkup()
        markup.row_width = markup_row_width
        for button in buttons:
            ikb = InlineKeyboardButton(
                text=button['text'][client.lang],
                callback_data=button['cb_data']
            )
            markup.add(ikb)
    return bot.send_message(client.cid, text, parse_mode, reply_markup=markup)

def check_conn_data_errors(client: VpnClient) -> list:
    errors = []

    # Check host (ip or dns-name)
    if match(r'\d{1,3}\.*', client.host):
        try:
            ip_address(client.host)
        except ValueError:
            errors.append('incorrect_ip')
    else:
        try:
            gethostbyname(client.host)
        except gaierror:
            errors.append('incorrect_hostname')
    
    # Check user
    if not match(r'^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$', client.user):
        errors.append('incorrect_username')

    # Check connection
    if not errors:
        try:
            with SSHClient() as ssh:
                ssh.set_missing_host_key_policy(AutoAddPolicy)
                ssh.exec_command
                ssh.connect(client.host, username=client.user, password=client.password,
                    look_for_keys=False, allow_agent=False)
        except (SSHException, socket_error):
            errors.append('ssh_error')
    return errors

def escape_chars(string: str) -> str:
    result = []
    escape_list = ['_', '*', '[', ']', '(', ')', '~', '`', '>', 
        '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in string:
        if char in escape_list:
            char = f'\{char}'
        result.append(char)
    return ''.join(result)

###################################################################################################
#                      Process BUILDS infinity loop
###################################################################################################
def process_builds(builds: Queue[Build]) -> None:
    while True:
        if builds.empty():
            sleep(1)
            continue
        build = builds.get_nowait()
        build.update()
        if build.status == 'in_progress':
            builds.put_nowait(build)
        elif build.status == 'success':
            successful_deploy(build)
        builds.task_done()
        sleep(1)
builds_thread = Thread(name='BuildsQueueThread', target=process_builds, args=(BUILDS,))
builds_thread.start()

###################################################################################################
#                      READ config, secret and messages file
###################################################################################################
with open(argv[1], 'rt', encoding='UTF-8') as fd:
    CONFIG = read_json(fd.read())

with open(argv[2], 'rt', encoding='UTF-8') as fd:
    SECRET = read_json(fd.read())

with open(argv[3], 'rt', encoding='UTF-8') as fd:
    MESSAGES = read_yaml(fd.read())

###################################################################################################
#                       Define BOT and HANDLERS
###################################################################################################
BOT = TeleBot(SECRET['bot']['token'])

# -------------------- START the BOT --------------------------------------------------------------
@BOT.message_handler(commands=['help', 'start'])
def welcome(msg: Message) -> None:
    try:
        client = VpnClient(msg.from_user.id, lang=msg.from_user.language_code)
        if not client.lang:
            client.lang = 'default'
        CLIENTS.update({client.cid: client})
        send_message(BOT, client, MESSAGES['welcome'], msg.json)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['welcome']['fallback'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- STOP the BOT ---------------------------------------------------------------
@BOT.message_handler(commands=['stop'])
def stop(msg: Message):
    try:
        client = CLIENTS[msg.from_user.id]
        BOT.clear_step_handler_by_chat_id(msg.from_user.id)
        send_message(BOT, client, MESSAGES['stop'])
    except Exception as ex:
        send_message(BOT, client, MESSAGES['stop']['fallback'])
        raise ex
    finally:
        del CLIENTS[msg.from_user.id]
# -------------------------------------------------------------------------------------------------

# -------------------- DETAILS --------------------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'details_cb')
def details_cb_query(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        send_message(BOT, client, MESSAGES['details'])
    except Exception as ex:
        send_message(BOT, client, MESSAGES['details']['fallback'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- F.A.Q. ---------------------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'faq_cb')
def faq_cb_query(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        send_message(BOT, client, MESSAGES['faq'])
    except Exception as ex:
        send_message(BOT, client, MESSAGES['faq']['fallback'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- STOP -----------------------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'stop_cb')
def stop_cb_query(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        stop(call.message)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['stop']['fallback'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- Give the HOST --------------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'go_cb')
def give_host(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        msg = send_message(BOT, client, MESSAGES['give_host'])
        BOT.register_next_step_handler(msg, set_host, client)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['give_host']['fallback'])
        raise ex

def set_host(msg: Message, client: VpnClient) -> None:
    client.host = msg.text.strip()
    give_user(client)
# -------------------------------------------------------------------------------------------------

# -------------------- Give the USER --------------------------------------------------------------
def give_user(client: VpnClient) -> None:
    try:
        msg = send_message(BOT, client, MESSAGES['give_user'])
        BOT.register_next_step_handler(msg, set_user, client)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['give_user']['fallback'])
        raise ex

def set_user(msg: Message, client: VpnClient) -> None:
    client.user = msg.text.strip()
    give_password(client)
# -------------------------------------------------------------------------------------------------

# -------------------- Give the PASSWORD ----------------------------------------------------------
def give_password(client: VpnClient) -> None:
    try:
        msg = send_message(BOT, client, MESSAGES['give_password'])
        BOT.register_next_step_handler(msg, set_password, client)
    except Exception as ex:
        message = MESSAGES['give_password']['fallback']['text'][client.lang]
        BOT.send_message(client.cid, message)
        raise ex

def set_password(msg: Message, client: VpnClient):
    client.password = msg.text.strip()
    delete_password(msg, client)

def delete_password(msg: Message, client: VpnClient):
    try:
        BOT.delete_message(msg.from_user.id, msg.id)
        send_message(BOT, client, MESSAGES['delete_password'])
    except Exception as ex:
        send_message(BOT, client, MESSAGES['common']['error'])
    confirm_conn_data(client)
# -------------------------------------------------------------------------------------------------

# -------------------- Confirm CONNECTION data ----------------------------------------------------
def confirm_conn_data(client: VpnClient) -> None:
    try:
        errors = check_conn_data_errors(client)
        env = {
            'host': escape_chars(client.host),
            'username': escape_chars(client.user),
            'password': escape_chars(client.password),
        }
        if errors:
            raise IncorrectConnectionData()
        else:
            send_message(BOT, client, MESSAGES['confirm_data'], env)
    except IncorrectConnectionData:
        send_message(BOT, client, MESSAGES['confirm_data']['fallback'], env)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['common']['error'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- Give VPN CLIENTS data ------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'req_clients_cd')
def give_clients(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        msg = send_message(BOT, client, MESSAGES['give_clients'])
        BOT.register_next_step_handler(msg, process_clients, client)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['give_clients']['fallback'])
        raise ex

def process_clients(msg: Message, client: VpnClient) -> None:
    try:
        if not match('^([A-Za-z0-9\-\_]{3,20}(\s+|$))+', msg.text.strip()):
            raise IncorrectVpnClientsData()
        else:
            client.vpn_clients = [vpn_client.strip() for vpn_client in msg.text.strip().split()]
            env = {'vpn_clients': client.vpn_clients}
            send_message(BOT, client, MESSAGES['process_clients'], env)
    except IncorrectVpnClientsData:
        send_message(BOT, client, MESSAGES['process_clients']['fallback'])
    except Exception as ex:
        send_message(BOT, client, MESSAGES['common']['error'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- Run DEPLOY -----------------------------------------------------------------
@BOT.callback_query_handler(func=lambda call: call.data == 'run_deploy_cd')
def run_deploy_cb_query(call: CallbackQuery) -> None:
    try:
        client = CLIENTS[call.from_user.id]
        BOT.edit_message_reply_markup(call.from_user.id, call.message.id)
        send_message(BOT, client, MESSAGES['run_deploy'])
        Thread(name=f'CreateBuild{client.cid}Thread', target=create_build, args=(client,)).start()
    except Exception as ex:
        send_message(BOT, client, MESSAGES['run_deploy']['fallback'])
        raise ex

def create_build(client: VpnClient):
    job_url = CONFIG['jenkins']['url'] + CONFIG['jenkins']['openvpn_deploy_job_uri']
    build_params = {
        'REMOTE_SERVER': client.host,
        'REMOTE_USER': client.user,
        'REMOTE_PASSWORD': client.password,
        'BUILD_ID': client.cid,
        'CLIENTS': ','.join(client.vpn_clients),
        'token': SECRET['jenkins']['openvpn_deploy_job_job_token']
    }
    auth = (SECRET['jenkins']['username'], SECRET['jenkins']['password'])
    client.build = Build(client.cid, job_url, build_params, auth)
    BUILDS.put_nowait(client.build)
# -------------------------------------------------------------------------------------------------

# -------------------- Successful deploy ----------------------------------------------------------
def successful_deploy(build: Build):
    try:
        client = CLIENTS[build.cid]
        send_message(BOT, client, MESSAGES['successful_deploy'])
        for name, artifact in build.get_artifacts().items():
            BOT.send_document(client.cid, BytesIO(artifact), visible_file_name=name)
    except Exception as ex:
        send_message(BOT, client, MESSAGES['successful_deploy']['fallback'])
        raise ex
# -------------------------------------------------------------------------------------------------

# -------------------- Failure deploy -------------------------------------------------------------
def failure_deploy():
    ...

BOT.infinity_polling()
