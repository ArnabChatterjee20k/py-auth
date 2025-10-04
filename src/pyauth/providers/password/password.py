from ..provider import Provider, InvalidAccount
from .payload import PasswordPayload
from ...models import Account, Role
import bcrypt


class Password(Provider):
    def __init__(self, *args):
        super().__init__(*args)

    async def create(self, payload: PasswordPayload) -> Account:
        self.validate_payload(payload)
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
        if not account:
            return None

        # Skip password verification in admin mode
        if not self._admin_operation:
            if not bcrypt.checkpw(
                payload.password.encode("utf-8"),
                account.password.encode("utf-8"),
            ):
                raise InvalidAccount("Password not matching")

        account.password = None
        return account

    async def update(self, payload: PasswordPayload, account: Account) -> Account:
        exclude = ["uid"]

        # Skip user verification in admin mode
        if not self._admin_operation:
            user = await self.get(payload)
            if not user:
                raise InvalidAccount("Invalid account")

        if account.password:
            # Hash the new password from the account object
            account.password = bcrypt.hashpw(
                account.password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
        else:
            exclude.append("password")
        storage = self.get_storage_session()
        updates = account.to_dict(exclude=exclude)
        new_account = await storage.update(Account, {"uid": account.uid}, updates)
        new_account.password = None
        return new_account

    async def delete(self, payload: PasswordPayload):
        # Skip account verification in admin mode
        if not self._admin_operation:
            account = await self.get(payload)
            if not account:
                raise InvalidAccount("Account not found")
        else:
            # In admin mode, get account directly by identifier
            storage = self.get_storage_session()
            account = await storage.get(Account, filters={"uid": payload.identifier})
            if not account:
                raise InvalidAccount("Account not found")

        storage = self.get_storage_session()
        return await storage.delete(Account, {"uid": account.uid})

    def _get_account(self, payload: PasswordPayload) -> Account:
        hashed_pw = bcrypt.hashpw(
            payload.password.encode("utf-8"), bcrypt.gensalt()
        ).decode(
            "utf-8"
        )  # safe to store in DB as str

        return Account(
            uid=payload.identifier,
            password=hashed_pw,
            **payload.to_dict(exclude=["identifier", "password"]),
        )

    @staticmethod
    def validate_payload(paylod: PasswordPayload):
        return PasswordPayload(**paylod.to_dict()).validate()
