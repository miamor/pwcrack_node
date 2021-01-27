from flask import Blueprint, Response
# from flask_login import current_user
from flask_httpauth import HTTPBasicAuth
from flask import jsonify, request, abort, send_file
from app.lib.base.provider import Provider
import json
import os
from app.utils.web_api import WebAPI
import web_cf

auth = HTTPBasicAuth()
web_api = WebAPI(web_cf.ip, web_cf.port, web_cf.username, web_cf.password)

bp = Blueprint('api', __name__)


@bp.route('/get_running_processes_commands', methods=['GET'])
def get_running_processes_commands():
    provider = Provider()
    hashcat = provider.hashcat()

    return jsonify(hashcat.get_running_processes_commands())


@bp.route('/session/<session_name>/<action>', methods=['GET'])
def hashcat_action(session_name, action):
    provider = Provider()
    sessions = provider.sessions()

    sessions_list = sessions.get(session_name=session_name)
    if len(sessions_list) == 0:
        return {'response': 'error', 'message': 'No session found'}
    session = sessions_list[0]
    

    if action == 'synchronize_from_node':
        user_data_path = sessions.session_filesystem.get_user_data_path(session.session.user_id, session.session.id)

        filepaths = []
        for filename in os.listdir(user_data_path):
            if filename != 'hashes.txt' and 'custom_wordlist' not in filename and 'pwd_wordlist' not in filename:
                filepaths.append(user_data_path+'/'+filename)

        result = web_api.up_to_web(session.session.id, filepaths=filepaths)


        # screen_log_file_path = session.hashcat.screen_log_file_path
        # potfile_path = sessions.session_filesystem.get_potfile_path(session.session.user_id, session.session.id)
        # cracked_path = sessions.session_filesystem.get_crackedfile_path(session.session.user_id, session.session.id)

        # result = web_api.up_to_web(session.session.id, filepaths=[screen_log_file_path, potfile_path, cracked_path])

        if result is False:
            return {'response': 'error', 'message': 'Something wrong when running web_api.up_to_web()'}
        return {'response': 'ok'}
    else:
        result = sessions.hashcat_action(session.session.id, action)
        if result is False:
            return {'response': 'error', 'message': 'Something wrong when running hashcat_action()'}
        return {'response': 'ok'}


@bp.route('/create_session', methods=['POST'])
def create_session():
    provider = Provider()
    sessions = provider.sessions()

    try:
        # print('request.form', request.form)
        data = json.loads(request.form.get('json'))
        num_files = data['num_files']
        session_record = data['session_record']
        # hashcat_record = data['hashcat_record']
        # print('[create_session] data', data)

        user_data_path = sessions.session_filesystem.get_user_data_path(session_record['user_id'], session_record['id'])

        for idx in range(num_files):
            file = request.files['file__{}'.format(idx)]
            save_as = user_data_path+'/'+file.filename
            file.save(save_as)

        session = sessions.create(session_record)
        # hashcat = sessions.create_hashcat_record(hashcat_record)

        res = {"response": "ok"}

        return res
    except Exception as e:
        traceback.print_exc()

        return {
            "response": "error",
            "message": str(e),
        }


@bp.route('/sync_hashcat_session', methods=['POST'])
def sync_hashcat_session():
    provider = Provider()
    sessions = provider.sessions()
    wordlists = provider.wordlists()
    rules = provider.rules()

    try:
        # print('request.form', request.form)
        data = json.loads(request.form.get('json'))
        num_files = data['num_files']
        session_record = data['session_record']
        hashcat_record = data['hashcat_record']

        user_data_path = sessions.session_filesystem.get_user_data_path(session_record['user_id'], session_record['id'])

        if hashcat_record['wordlist_type'] == 0:
            hashcat_record['wordlist'] = wordlists.get_wordlist_path(hashcat_record['wordlist'])
        else:
            hashcat_record['wordlist'] = user_data_path+'/'+hashcat_record['wordlist']
        
        hashcat_record['rule'] = rules.get_rule_path(hashcat_record['rule'])

        if num_files > 0:
            for idx in range(num_files):
                file = request.files['file__{}'.format(idx)]
                save_as = user_data_path+'/'+file.filename
                file.save(save_as)

        hashcat = sessions.create_hashcat_record(hashcat_record)

        res = {"response": "ok"}

        return res
    except Exception as e:
        traceback.print_exc()

        return {
            "response": "error",
            "message": str(e),
        }


@bp.route('/sync_session', methods=['POST'])
def sync_session():
    provider = Provider()
    sessions = provider.sessions()

    data = request.get_json(force=True)
    session_record = data['session_record']

    sessions.update(session_record['id'], session_record)

    res = {"response": "ok"}

    return res


@bp.route('/get_wordlists_from_node', methods=['GET'])
def get_wordlists_from_node():
    provider = Provider()
    wordlists = provider.wordlists()

    wordlist_paths = wordlists.get_wordlists(return_path=False)

    return wordlist_paths


@bp.route('/get_rules_from_node', methods=['GET'])
def get_rules_from_node():
    provider = Provider()
    rules = provider.rules()

    rules_paths = rules.get_rules(return_path=False)

    return rules_paths


@bp.route('/is_valid_local_wordlist', methods=['POST'])
def is_valid_local_wordlist():
    provider = Provider()
    wordlists = provider.wordlists()

    data = request.get_json(force=True)
    wordlist_path = wordlists.get_wordlist_path(data['wordlist_filename'])

    return {'exist': os.path.exists(wordlist_path)}


@bp.route('/is_valid_local_rule', methods=['POST'])
def is_valid_local_rule():
    provider = Provider()
    rules = provider.rules()

    data = request.get_json(force=True)
    rule_path = rules.get_rule_path(data['rule_filename'])

    return {'exist': os.path.exists(rule_path)}


@bp.route('/upload_wordlist', methods=['POST'])
def upload_wordlist():
    provider = Provider()
    wordlists = provider.wordlists()
    wordlist_path = wordlists.wordlist_path


@bp.route('/update_hashcat_settings', methods=['POST'])
def update_hashcat_settings():
    provider = Provider()
    settings = provider.settings()

    data = request.get_json(force=True)

    hashcat_binary = data['hashcat_binary'].strip()
    hashcat_rules_path = data['hashcat_rules_path'].strip()
    wordlists_path = data['wordlists_path'].strip()
    uploaded_hashes_path = data['uploaded_hashes_path'].strip()
    hashcat_status_interval = int(data['hashcat_status_interval'])
    hashcat_force = int(data['hashcat_force'])

    has_errors = False
    msg = ''
    if len(hashcat_binary) == 0 or not os.path.isfile(hashcat_binary):
        has_errors = True
        msg = 'Hashcat executable does not exist'
    elif not os.access(hashcat_binary, os.X_OK):
        has_errors = True
        msg = 'Hashcat file is not executable'

    if len(hashcat_rules_path) == 0 or not os.path.isdir(hashcat_rules_path):
        has_errors = True
        msg = 'Hashcat rules directory does not exist', 'error'
    elif not os.access(hashcat_rules_path, os.R_OK):
        has_errors = True
        msg = 'Hashcat rules directory is not readable'

    if len(wordlists_path) == 0 or not os.path.isdir(wordlists_path):
        has_errors = True
        msg = 'Wordlist directory does not exist'
    elif not os.access(wordlists_path, os.R_OK):
        has_errors = True
        msg = 'Wordlist directory is not readable'

    if len(uploaded_hashes_path) == 0 or not os.path.isdir(uploaded_hashes_path):
        has_errors = True
        msg = 'Uploaded Hashes directory does not exist'
    elif len(uploaded_hashes_path) > 0 and not os.access(uploaded_hashes_path, os.R_OK):
        has_errors = True
        msg = 'Uploaded Hashes directory is not readable'

    if hashcat_status_interval <= 0:
        hashcat_status_interval = 10

    if has_errors:
        return {'response': 'error', 'message': 'Some fields missing'}

    settings.save('hashcat_binary', hashcat_binary)
    settings.save('hashcat_rules_path', hashcat_rules_path)
    settings.save('wordlists_path', wordlists_path)
    settings.save('uploaded_hashes_path', uploaded_hashes_path)
    settings.save('hashcat_status_interval', hashcat_status_interval)
    settings.save('hashcat_force', hashcat_force)

    # When settings are saved, run system updates.
    system = provider.system()
    system.run_updates()

    return {'response': 'ok'}

