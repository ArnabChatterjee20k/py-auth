https://chatgpt.com/c/68b55368-9e44-8327-a20e-c0dc6dc7bbe6
# Why another simple auth lib?
I am just scared of the python auth libraries currently present. I dont play and fight with methods.
I will be just able to plug my adapters for every layers and thats it.

# Whole Flow
User Request (login/signup/etc)
        │
        ▼
 ┌───────────────────┐
 │   AuthProvider    │   e.g. Password() / Oauth()
 └───────────────────┘
        │
        │  (1) validate credentials / tokens
        │  (2) produce session_id / token / user_id
        ▼
 ┌───────────────────┐
 │     Storage       │   e.g. InMemory() / SQL() / Redis()
 └───────────────────┘
        │
        │  (3a) If signup → insert new user record in `schema`
        │  (3b) If login → check user exists in `schema`
        │  (3c) Store sessions mapped to user_id
        ▼
 ┌───────────────────┐
 │   Permissions     │   e.g. RBAC() / ReBAC()
 └───────────────────┘
        │
        │  (4) check what user is allowed to do
        ▼
   Response back to user

Token = jwt => representing authentication state rather the authentication process itself


# Improvements
[] Flexible non restricted data schemas -> need to map to the storage layer as well for that we need to interally map