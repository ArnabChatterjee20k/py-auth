from ..provider import Provider, InvalidAccount
from .payload import PasswordPayload
from ...models import Account, Role
import bcrypt


class Password(Provider):
    def __init__(self, *args):
        super().__init__(*args)

    async def create(self, payload: PasswordPayload) -> Account:
        self.validate_paylod(payload)
        # needed bytes
        account = self._get_account(payload)
        storage = self.get_storage_session()
        return await storage.create(account)

    async def get(self, payload: PasswordPayload) -> Account | None:
        self.validate_payload(payload)
        storage = self.get_storage_session()

        account: Account = await storage.get(
            Account, filters={"uid": payload.identifier}
        )
        if account and bcrypt.checkpw(
            payload.password.encode("utf-8"), account.password.encode("utf-8")
        ):
            return account
        return None

    async def update(self, payload: PasswordPayload, account: Account) -> Account:
        exclude = ["uid"]
        if account.password:
            account.password = self._get_account(payload).password
        else:
            exclude.append("password")
        storage = self.get_storage_session()
        updates = account.to_dict(exclude=exclude)
        return await storage.update(Account, {"uid": account.uid}, updates)

    async def delete(self, payload: PasswordPayload):
        account = await self.get(payload)
        if not account:
            raise InvalidAccount("Account not found")
        storage = self.get_storage_session()
        return await storage.delete(Account, {"uid": account.uid})

    def _get_account(self, payload: PasswordPayload) -> Account:
        password = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt())
        return Account(uid=payload.identifier, password=password)

    @staticmethod
    def validate_paylod(paylod: PasswordPayload):
        return PasswordPayload(**paylod.to_dict()).validate()
