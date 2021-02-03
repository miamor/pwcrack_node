from app.lib.base.settings import SettingsManager
from app.lib.session.manager import SessionManager
from app.lib.screen.manager import ScreenManager
from app.lib.hashcat.manager import HashcatManager
from app.lib.base.shell import ShellManager
from app.lib.base.wordlists import WordlistManager
from app.lib.base.system import SystemManager
from app.lib.base.filesystem import FileSystemManager
from app.lib.base.rules import RulesManager
from app.lib.base.hashes import HashesManager
# from flask_login import current_user


class Provider:
    def settings(self):
        settings = SettingsManager()
        return settings

    def sessions(self):
        session = SessionManager(
            self.hashcat(),
            self.screens(),
            self.wordlists(),
            self.filesystem(),
            self.shell()
        )
        return session

    def screens(self):
        return ScreenManager(self.shell())

    def hashcat(self):
        settings = self.settings()
        return HashcatManager(
            self.shell(),
            settings.get('hashcat_binary', ''),
            status_interval=int(settings.get('hashcat_status_interval', 10)),
            force=int(settings.get('hashcat_force', 0))
        )

    def shell(self):
        # If there is no current_user it means we're in the cron job.
        # user_id = current_user.id if current_user else 0
        user_id = 0
        return ShellManager(user_id=user_id)

    def wordlists(self):
        settings = self.settings()
        return WordlistManager(self.filesystem(), settings.get('wordlists_path', ''))

    def system(self):
        return SystemManager(
            self.shell(),
            self.settings()
        )

    def filesystem(self):
        return FileSystemManager()

    def rules(self):
        settings = self.settings()
        return RulesManager(self.filesystem(), settings.get('hashcat_rules_path', ''))

    def hashes(self):
        settings = self.settings()
        return HashesManager(self.filesystem(), settings.get('uploaded_hashes_path', ''))
