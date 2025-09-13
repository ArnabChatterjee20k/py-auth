from ..provider import Provider
from .payload import PasswordPayload
from ...models import Account, Role
import bcrypt


class Password(Provider):
    def __init__(self, *args):
        super().__init__(*args)

    def create_account(self, payload: PasswordPayload):
        payload.password = bcrypt.hashpw(payload.password, bcrypt.gensalt())
        account = self._storage.create(Account.__name__, **{**payload.to_dict()})
        data = self.get_model_from_dict(Account, account)
        return data

    @staticmethod
    def validate_paylod(paylod: PasswordPayload):
        return PasswordPayload(**paylod.to_dict()).validate()
