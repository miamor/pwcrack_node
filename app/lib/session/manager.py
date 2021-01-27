import re
import random
import string
import os
import datetime
import time
from app.lib.models.sessions import SessionModel, SessionNotificationModel
from app.lib.models.hashcat import HashcatModel, HashcatHistoryModel
from app.lib.session.filesystem import SessionFileSystem
from app.lib.session.instance import SessionInstance
from app.lib.hashcat.instance import HashcatInstance
from app import db
from sqlalchemy import and_, desc
from flask import send_file


class SessionManager:
    def __init__(self, hashcat, screens, wordlists, filesystem, shell):
        self.hashcat = hashcat
        self.screens = screens
        self.wordlists = wordlists
        self.filesystem = filesystem
        self.shell = shell
        self.session_filesystem = SessionFileSystem(filesystem)
        self.cmd_sleep = 2

    def exists(self, user_id, name, active=True):
        return self.__get(user_id, name, active) is not None

    def __get(self, user_id, name, active):
        return SessionModel.query.filter(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.name == name,
                SessionModel.active == active
            )
        ).first()

    def __get_by_id(self, session_id):
        return SessionModel.query.filter(SessionModel.id == session_id).first()

    def __get_by_name(self, session_name):
        return SessionModel.query.filter(SessionModel.name == session_name).first()

    def create(self, data):
        # If it exists (shouldn't), return it.
        session = self.__get(data['user_id'], data['name'], True)
        if session:
            return self.update(session.id, data)

        session = SessionModel(
            id=data['id'],
            user_id=data['user_id'],
            smode=data['smode'],
            filename=data['filename'],
            name=data['name'],
            description=data['description'],
            screen_name=data['screen_name'],
            active=data['active'],
            # notifications_enabled=data['notifications_enabled'],
            # terminate_at=datetime.datetime.fromisoformat(data['terminate_at']),
            # created_at=datetime.datetime.fromisoformat(data['created_at']),
        )
        db.session.add(session)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(session)

        return session

    def get(self, user_id=0, session_id=0, session_name=None, active=None):
        query = SessionModel.query
        if user_id > 0:
            query = query.filter(SessionModel.user_id == user_id)

        if session_id > 0:
            query = query.filter(SessionModel.id == session_id)

        if session_name is not None:
            query = query.filter(SessionModel.name == session_name)

        if active is not None:
            query = query.filter(SessionModel.active == active)

        sessions = query.all()

        data = []
        for session in sessions:
            hashcat_instance = HashcatInstance(session, self.session_filesystem, self.hashcat, self.wordlists)
            instance = SessionInstance(session, hashcat_instance, self.session_filesystem)
            data.append(instance)

        return data

    def __get_hashcat_record(self, session_id):
        return HashcatModel.query.filter(HashcatModel.session_id == session_id).first()

    def update_hashcat_record(self, session_id, update_dict):
        record = self.__get_hashcat_record(session_id)
        if not record:
            record = self.create_hashcat_record(update_dict)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'mode':
                record.mode = val
            elif key == 'hashtype':
                record.hashtype = val
            elif key == 'wordlist':
                record.wordlist = val
            elif key == 'rule':
                record.rule = val
            elif key == 'mask':
                record.mask = val
            elif key == 'increment_min':
                record.increment_min = val
            elif key == 'increment_max':
                record.increment_max = val
            elif key == 'optimised_kernel':
                record.optimised_kernel = val
            elif key == 'wordlist_type':
                record.wordlist_type = val
            elif key == 'workload':
                record.workload = val
            elif key == 'optimised_kernel':
                record.optimised_kernel = val
            elif key == 'created_at':
                record.created_at = datetime.datetime.fromisoformat(val)

        db.session.commit()
        db.session.refresh(record)
        return True

    def create_hashcat_record(self, data):
        session = self.__get_hashcat_record(data['session_id'])
        if session:
            return self.update_hashcat_record(data['session_id'], data)

        record = HashcatModel(
            id=data['id'],
            session_id=data['session_id'],
            mode=data['mode'],
            workload=data['workload'],
            hashtype=data['hashtype'],
            wordlist=data['wordlist'],
            wordlist_type=data['wordlist_type'],
            rule=data['rule'],
            mask=data['mask'],
            increment_min=data['increment_min'],
            increment_max=data['increment_max'],
            optimised_kernel=data['optimised_kernel'],
            created_at=datetime.datetime.fromisoformat(data['created_at'])
        )

        db.session.add(record)
        db.session.commit()
        # In order to get the created object, we need to refresh it.
        db.session.refresh(record)

        return record

    def export_cracked_passwords(self, session_id, save_as):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        command = self.hashcat.build_export_password_command_line(
            self.session_filesystem.get_hashfile_path(session.user_id, session_id),
            self.session_filesystem.get_potfile_path(session.user_id, session_id),
            save_as
        )
        self.shell.execute(command)

        return True

    def hashcat_action(self, session_id, action):
        # First get the session.
        session = self.get(session_id=session_id)[0]

        # Make sure the screen is running.
        screen = self.screens.get(session.screen_name, log_file=self.session_filesystem.get_screenfile_path(session.user_id, session_id))

        if screen is False:
            return False

        if action == 'start':
            if self.__is_past_date(session.terminate_at):
                return False

            command = self.hashcat.build_command_line(
                session.screen_name,
                int(session.hashcat.mode),
                session.hashcat.mask,
                session.hashcat.hashtype,
                self.session_filesystem.get_hashfile_path(session.user_id, session_id),
                session.hashcat.wordlist_path,
                session.hashcat.rule_path,
                self.session_filesystem.get_crackedfile_path(session.user_id, session_id),
                self.session_filesystem.get_potfile_path(session.user_id, session_id),
                int(session.hashcat.increment_min),
                int(session.hashcat.increment_max),
                int(session.hashcat.optimised_kernel),
                int(session.hashcat.workload)
            )

            # Before we start a new session, rename the previous "screen.log" file
            # so that we can determine errors/state easier.
            self.session_filesystem.backup_screen_log_file(session.user_id, session_id)

            # Even though we renamed the file, as it is still open the OS handle will now point to the renamed file.
            # We re-set the screen logfile to the original file.
            screen.set_logfile(self.session_filesystem.get_screenfile_path(session.user_id, session_id))
            screen.execute(command)
        elif action == 'reset':
            # Close the screen.
            screen.quit()

            # Create it again.
            screen = self.screens.get(session.screen_name, log_file=self.session_filesystem.get_screenfile_path(session.user_id, session_id))
        elif action == 'resume':
            if self.__is_past_date(session.terminate_at):
                return False

            # Hashcat only needs 'r' to resume.
            screen.execute({'r': ''})

            # Wait a couple of seconds.
            time.sleep(self.cmd_sleep)

            # Send an "s" command to show current status.
            screen.execute({'s': ''})

            # Wain a second.
            time.sleep(1)
        elif action == 'pause':
            # Hashcat only needs 'p' to pause.
            screen.execute({'p': ''})

            # Wait a couple of seconds.
            time.sleep(self.cmd_sleep)

            # Send an "s" command to show current status.
            screen.execute({'s': ''})

            # Wain a second.
            time.sleep(1)
        elif action == 'stop':
            # Send an "s" command to show current status.
            screen.execute({'s': ''})

            # Wain a second.
            time.sleep(1)

            # Hashcat only needs 'q' to pause.
            screen.execute({'q': ''})
        elif action == 'restore':
            if self.__is_past_date(session.terminate_at):
                return False

            # To restore a session we need a command line like 'hashcat --session NAME --restore'.
            command = self.hashcat.build_restore_command(session.screen_name)
            screen.execute(command)

            # Wait a couple of seconds.
            time.sleep(self.cmd_sleep)

            # Send an "s" command to show current status.
            screen.execute({'s': ''})

            # Wain a second.
            time.sleep(1)
        else:
            return False

        return True

    def __is_past_date(self, date):
        return datetime.datetime.now() > date

    def terminate_past_sessions(self):
        # Get all sessions which have terminate_at set as a past datetime.
        print("Trying to get past sessions...")
        past_sessions = SessionModel.query.filter(SessionModel.terminate_at < datetime.datetime.now()).all()
        for past_session in past_sessions:
            # Check if session is currently running.
            print("Loading session %d" % past_session.id)
            session = self.get(past_session.user_id, past_session.id)
            if len(session) == 0:
                print("Session %d does not exist" % past_session.id)
                continue
            print("Session %d loaded" % past_session.id)
            session = session[0]

            status = session.hashcat.state
            if status == 1 or status == 4:
                # If it's running or paused, terminate.
                print("Terminating session %d" % past_session.id)
                self.hashcat_action(session.id, 'stop')

    def get_data_files(self, user_id, session_id):
        user_data_path = self.session_filesystem.get_user_data_path(user_id, session_id)
        return self.filesystem.get_files(user_data_path)


    def update(self, session_id, update_dict):
        session = self.__get_by_id(session_id)

        for key in list(update_dict.keys()):
            val = update_dict[key]
            if key == 'smode':
                session.smode = val
            elif key == 'filename':
                session.filename = val
            elif key == 'description':
                session.description = val
            elif key == 'active':
                session.active = val
            elif key == 'terminate_at':
                session.terminate_at = datetime.datetime.fromisoformat(val)
            elif key == 'created_at':
                session.created_at = datetime.datetime.fromisoformat(val)
            elif key == 'screen_name':
                session.screen_name = val

        db.session.commit()
        db.session.refresh(session)
        return True

    def delete(self, session_id):
        session = self.get(session_id=session_id)
        if not session or len(session) == 0:
            # If we can't get the session, consider it deleted - MIND GAMES!
            return True

        session = session[0]
        if session.hashcat.state in [1, 4]:
            # Session is either running or paused.
            return False

        # Delete data first.
        data_path = self.session_filesystem.get_user_data_path(session.user_id, session.id)
        if os.path.isdir(data_path):
            self.session_filesystem.delete_path(data_path)

        # Now delete database records.
        HashcatModel.query.filter_by(session_id=session.id).delete()
        # HashcatHistoryModel.query.filter_by(session_id=session.id).delete()
        # SessionNotificationModel.query.filter_by(session_id=session.id).delete()
        SessionModel.query.filter_by(id=session.id).delete()

        db.session.commit()
        return True
