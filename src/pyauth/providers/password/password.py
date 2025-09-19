from ..provider import Provider
from .payload import PasswordPayload
from ...models import Account, Role
import bcrypt


class Password(Provider):
    def __init__(self, *args):
        super().__init__(*args)

    def create_account(self, payload: PasswordPayload):
        payload.password = bcrypt.hashpw(payload.password, bcrypt.gensalt())
        account = Account(**payload.to_dict())
        return account

    @staticmethod
    def validate_paylod(paylod: PasswordPayload):
        return PasswordPayload(**paylod.to_dict()).validate()
