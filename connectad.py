from ldap3 import Server, Connection, ALL_ATTRIBUTES, ALL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES


def convert_entries_to_list(user_entries):
    user = []
    for ex in user_entries:
        user_data = {}
        # //Check Error Empty Data in Attributes
        # try:
        user_data['Displayname'] = ex['attributes']['Displayname']
        user_data['Distinguishedname'] = ex['attributes']['distinguishedname']
        user_data['Email'] = ex['attributes']['mail']
        user_data['department'] = ex['attributes']['department']
        user_data['OptionalEmail'] = ex['attributes']['OptionalEmail']
        user_data['sAMAccountname'] = ex['attributes']['samaccountname']
        user_data['LastLogon'] = ex['attributes']['lastlogontimestamp']
        user_data['info'] = ex['attributes']['info']
        user_data['LastPwdChange'] = ex['attributes']['pwdlastset']
        user_data['AccountExpires'] = ex['attributes']['accountExpires']
        user_data['extensionAttribute1'] = ex['attributes']['extensionAttribute1']
        user_data['extensionAttribute2'] = ex['attributes']['extensionAttribute2']
        user_data['extensionAttribute3'] = ex['attributes']['extensionAttribute3']
        user_data['extensionAttribute4'] = ex['attributes']['extensionAttribute4']
        user_data['extensionAttribute5'] = ex['attributes']['extensionAttribute5']
        user_data['extensionAttribute6'] = ex['attributes']['extensionAttribute6']
        user_data['extensionAttribute7'] = ex['attributes']['extensionAttribute7']
        user_data['extensionAttribute8'] = ex['attributes']['extensionAttribute8']
        user_data['extensionAttribute9'] = ex['attributes']['extensionAttribute9']
        user_data['extensionAttribute10'] = ex['attributes']['extensionAttribute10']
        user_data['extensionAttribute11'] = ex['attributes']['extensionAttribute11']
        user_data['extensionAttribute12'] = ex['attributes']['extensionAttribute12']
        user_data['extensionAttribute13'] = ex['attributes']['extensionAttribute13']
        user_data['extensionAttribute14'] = ex['attributes']['extensionAttribute14']
        user_data['extensionAttribute15'] = ex['attributes']['extensionAttribute15']
        user_data['MemberOf'] = ex['attributes']['memberof']
        user_data['title'] = ex['attributes']['title']
        user_data['objectClass'] = ex['attributes']['objectClass']
        
        # //Check Error Empty Data in Attributes
        # except KeyError as e: 
        #     user_data[str(e)] = 'fix'
        #     print('ERROR--------------------->' + str(e) +
        #           'username : ' + ex['attributes']['distinguishedname'])
        #     pass
        
        user.append(user_data)
    return user


class ActiveDirectoryAPI:
    # //Check Authentication
    def ad_auth_ldap(self, adserver, domain, user, password):
        s = Server(adserver, get_info=ALL)
        user_dn = user + '@' + domain
        print(user_dn)
        c = Connection(s, user=user_dn, password=password)
        if not c.bind():
            print('error in bind : {}', c.result)
        c.unbind()
        r = c.result
        return r

    # //Get Attributes "Non" Standards ex. extensionattribute1, optionalemail
    def get_attributes_ad(self, adserver, ousearch, binduser, password, usersearch):
        filters = '(&(objectclass=person)(name=' + usersearch + '))'
        server = Server(adserver, get_info=ALL)

        attribs = ['CN', 'Distinguishedname', 'displayname', 'mail', 'department', 'optionalemail', 'samaccountname',
                   'lastlogontimestamp', 'info', 'pwdlastset', 'accountexpires', 'accountexpires', 'extensionattribute1',
                   'extensionattribute2', 'extensionattribute3', 'extensionattribute4', 'extensionattribute5', 'extensionattribute6', 
                   'extensionattribute7', 'extensionattribute8', 'extensionattribute9', 'extensionattribute10', 'extensionattribute11', 
                   'extensionattribute12', 'extensionattribute13', 'extensionattribute14', 'extensionattribute15', 'memberof','title', 'objectclass']
        try:
            conn = Connection(server, binduser, password, auto_bind=True)
            conn.search(ousearch, filters, attributes = attribs, paged_size = 5)
            entry = conn.response
        except Exception as e:
            print('ERROR--------------->{}', e)

        results = convert_entries_to_list(entry)

        #print(conn.entries[0].entry_to_ldif()) //Check Opject retrive from AD
        conn.unbind()

        return results

    # //Get Attributes Standards
    def get_attributes_ad_standard(self, adserver, ousearch, binduser, password, usersearch):
        filters = '(&(objectclass=person)(name=' + usersearch + '))'
        server = Server(adserver, get_info=ALL)

        attribs = ['CN', 'Distinguishedname', 'displayname', 'mail', 'department', 'samaccountname',
            'lastlogontimestamp', 'info', 'pwdlastset', 'accountexpires', 'accountexpires', 'memberof','title', 'objectclass','userPrincipalName']
        
        try:
            conn = Connection(server, binduser, password, auto_bind=True)
            conn.search(ousearch, filters, attributes = attribs)
            entry = conn.response
        except Exception as e:
            print('ERROR--------------->{}', e)
        print(conn.entries[0].entry_to_ldif()) 
        conn.unbind()
        user = []
        for ex in entry:
            user_data = {}
            user_data['Displayname'] = ex['attributes']['Displayname']
            user_data['Distinguishedname'] = ex['attributes']['distinguishedname']
            user_data['Email'] = ex['attributes']['mail']
            user_data['department'] = ex['attributes']['department']
            user_data['sAMAccountname'] = ex['attributes']['samaccountname']
            user_data['LastLogon'] = ex['attributes']['lastlogontimestamp']
            user_data['info'] = ex['attributes']['info']
            user_data['LastPwdChange'] = ex['attributes']['pwdlastset']
            user_data['AccountExpires'] = ex['attributes']['accountExpires']
            user_data['MemberOf'] = ex['attributes']['memberof']
            user_data['title'] = ex['attributes']['title']
            user_data['objectClass'] = ex['attributes']['objectClass']
            user_data['userPrincipalName'] = ex['attributes']['userPrincipalName']
            user.append(user_data)
        return user
