from ldap3 import Server, Connection, ALL_ATTRIBUTES, ALL, SUBTREE, MODIFY_REPLACE, Tls
import json
import ssl


class ADCLASS:
    def test_ad_class(self):
        return 'ADCLASS'

    def gets_ad_information(self, AD_SERVER, OU_SEARCH, BIND_USENAME, BIN_USERPASSWORD, SEARCH_USERS, ATTRIBUTES_LIST):
        tls_config = Tls(validate=ssl.CERT_NONE)
        filters = '(&(objectclass=user)(name=' + SEARCH_USERS + '))'
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        print(AD_SERVER, OU_SEARCH, BIND_USENAME,
              BIN_USERPASSWORD, SEARCH_USERS, ATTRIBUTES_LIST)

        try:
            conn = Connection(server, BIND_USENAME, BIN_USERPASSWORD)
            conn.start_tls()
            conn.bind()
            conn.search(OU_SEARCH, filters,
                        attributes=ATTRIBUTES_LIST, paged_size=5,
                        paged_cookie=5, search_scope=SUBTREE)
            rs_respone = conn.response
            conn.unbind()
        except Exception as e:
            print('ERROR--------------->{}'.format(e))
            return 'ERROR from get_ad_info()--->{}'.format(e)

        user_info_list = []
        for ex in rs_respone:
            user_data = {}
            for i in ATTRIBUTES_LIST:
                user_data[i] = ex['attributes'][i]
            user_info_list.append(user_data)

        return user_info_list

    def modify_ad_password(self, AD_SERVER, BIND_USENAME, BIN_USERPASSWORD, USER_CN, NEW_PASSWORD):

        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        print(AD_SERVER, BIND_USENAME,
              BIN_USERPASSWORD, USER_CN, NEW_PASSWORD)

        try:
            conn = Connection(server, BIND_USENAME, BIN_USERPASSWORD)
            conn.start_tls()
            conn.bind()
            conn.extend.microsoft.modify_password(USER_CN, NEW_PASSWORD)
            rs_mod = conn.result
            conn.unbind()
        except Exception as e:
            print('ERROR--------------->{}'.format(e))
            return 'ERROR from get_ad_info()--->{}'.format(e)

        return 'Operation Modify Password Result : {}'.format(rs_mod)
    
    def modify_ad_attributes(self, AD_SERVER, BIND_USENAME, BIN_USERPASSWORD, USER_CN, ATTRIBUTE_NAME, NEW_VALUE):
        
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_SERVER, port=636, use_ssl=True,
                        tls=tls_config, get_info=ALL)

        print(AD_SERVER, BIND_USENAME, BIN_USERPASSWORD,
              USER_CN, ATTRIBUTE_NAME, NEW_VALUE)

        try:
            conn = Connection(server, BIND_USENAME, BIN_USERPASSWORD)
            conn.start_tls()
            conn.bind()
            conn.modify(USER_CN, {ATTRIBUTE_NAME: [
                        (MODIFY_REPLACE, [NEW_VALUE])]})
            rs_mod = conn.result
            conn.unbind()
        except Exception as e:
            print('ERROR--------------->{}'.format(e))
            return 'ERROR from get_ad_info()--->{}'.format(e)

        return 'Operation Modify Attributes Result : {}'.format(rs_mod)
