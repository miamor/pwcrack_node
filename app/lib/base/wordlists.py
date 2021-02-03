import os


class WordlistManager:
    def __init__(self, filesystem, wordlist_path):
        self.filesystem = filesystem
        self.wordlist_path = wordlist_path

    def get_wordlists__(self, return_path=True):
        files = self.filesystem.get_files(self.wordlist_path, recursive=True, return_path=return_path)
        folders = self.filesystem.get_folders(self.wordlist_path, recursive=True, return_path=return_path)
        return {**files, **folders}

    def get_wordlists(self, return_path=True):
        return self.filesystem.get_files(self.wordlist_path, return_path=return_path)

    def is_valid_wordlist(self, wordlist):
        wordlists = self.get_wordlists()
        return wordlist in wordlists

    def get_wordlist_path(self, wordlist):
        if not self.is_valid_wordlist(wordlist):
            return ''

        wordlists = self.get_wordlists()
        wordlist = wordlists[wordlist]
        return wordlist['path']

    def get_name_from_path(self, path):
        return path.replace(self.wordlist_path, '').lstrip(os.sep)
