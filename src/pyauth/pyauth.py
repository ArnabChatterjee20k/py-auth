from providers import Provider


class Pyauth:
    def __init__(self, provider: Provider):
        self._provider = provider

    # account
    def create_account(self):
        pass

    def logout_account(self):
        pass

    def get_account(self):
        pass

    def delete_account(self):
        pass

    def update_account(self):
        pass

    def block_account(self):
        pass

    def verify_account(self):
        pass

    def get_sessions(self):
        pass

    # session
    def start_session(self):
        pass

    def end_session(self):
        pass

    def get_current_account(self):
        pass

    # roles
    def assign_role(self):
        pass

    def update_role(self):
        pass

    def verify_role(self):
        pass

    def get_roles(self):
        pass

    # rate-limit/throttling/control
    def set_attempts(self):
        pass

    # helpers/decorators
    def require_auth(self):
        pass

    def require_role(self):
        pass
