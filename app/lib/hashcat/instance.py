import os
from app.lib.models.hashcat import HashcatModel


class HashcatInstance:
    def __init__(self, session, filesystem, manager, wordlists):
        self.session = session
        self.filesystem = filesystem
        self.hashcat = manager
        self.wordlists = wordlists
        self.settings = HashcatModel.query.filter(HashcatModel.session_id == session.id).first()

        self._screen_log_file_path = None

    @property
    def screen_log_file_path(self):
        if self._screen_log_file_path is None:
            self._screen_log_file_path = self.filesystem.find_latest_screenlog(self.session.user_id, self.session.id)
        return self._screen_log_file_path

    @property
    def increment_min(self):
        return self.settings.increment_min if self.settings else 0

    @property
    def increment_max(self):
        return self.settings.increment_max if self.settings else 0

    @property
    def increment_enabled(self):
        return self.increment_min > 0 and self.increment_max > 0

    @property
    def mode(self):
        return self.settings.mode if self.settings else ''

    @property
    def hashtype(self):
        return self.settings.hashtype if self.settings else ''

    @property
    def wordlist_type(self):
        return self.settings.wordlist_type if self.settings else 0

    @property
    def wordlist_path(self):
        return self.settings.wordlist if self.settings else ''

    @property
    def wordlist(self):
        return self.wordlists.get_name_from_path(self.wordlist_path) if self.settings else ''

    @property
    def rule_path(self):
        return self.settings.rule if self.settings else ''

    @property
    def rule(self):
        return os.path.basename(self.settings.rule) if self.settings else ''

    @property
    def mask(self):
        return self.settings.mask if self.settings else ''

    @property
    def optimised_kernel(self):
        return self.settings.optimised_kernel if self.settings else 0

    @property
    def workload(self):
        return 2 if self.settings.workload is None else int(self.settings.workload)

    @property
    def configured(self):
        return True if self.settings else False

