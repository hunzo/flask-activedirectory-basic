# "# flask-activedirectory-basic" 

# /POST /api/ad/searchinfo

- adserver = Active Directory Server
- ousearch = Organizetion Unit Search ex. ou=user,dc=domain,dc=local
- binduser = BindUser ex. binuser@domain.local
- bindpassword = BindUser Password
- searchuser = Searching username and get Attributes

# /POST /api/ad/auth

- adserver = Active Directory Server
- domain = Domain Name ex. @domain.local
- username = User Check ex. username@domain.local
- password = User Password

# /POST /api/adstandard/searchinfo 

- adserver = Active Directory Server
- domain = Domain Name ex. @domain.local
- username = User Check ex. username@domain.local
- password = User Password
