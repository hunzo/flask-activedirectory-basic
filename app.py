from flask import Flask, render_template,request,jsonify
from connectad import *


app = Flask(__name__)
@app.route('/')
def main():
    return render_template('index.html')

@app.route('/api/ad/auth', methods=['POST'])
def ad_auth():
    if request.method == 'POST':
        result = request.get_json('adserver')
        result = request.get_json('domain')
        result = request.get_json('username')
        result = request.get_json('password')

        authserver = result['adserver']
        domainname = result['domain']
        user = result['username']
        password = result['password']

        c = ActiveDirectoryAPI()
        r = c.ad_auth_ldap(authserver,domainname,user,password)
        
        return jsonify(r)

    return 'NONE'

@app.route('/api/ad/searchinfo', methods=['POST'])
def ad_get_info():
    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('ousearch')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('searchuser')
        
        adserver = results['adserver']
        ousearch = results['ousearch']
        binduser = results['binduser']
        bindpassword =  results['bindpassword']
        searchuser = results['searchuser']
        
        c = ActiveDirectoryAPI()
        rs = c.get_attributes_ad(adserver,ousearch,binduser,bindpassword,searchuser)
        print(rs)
        return jsonify(rs)
    return 'NONE'

@app.route('/api/adstandard/searchinfo', methods=['POST'])
def ad_get_standard_info():
    if request.method == 'POST':
        results = request.get_json('adserver')
        results = request.get_json('ousearch')
        results = request.get_json('binduser')
        results = request.get_json('bindpassword')
        results = request.get_json('searchuser')
        
        adserver = results['adserver']
        ousearch = results['ousearch']
        binduser = results['binduser']
        bindpassword =  results['bindpassword']
        searchuser = results['searchuser']
        
        conn = ActiveDirectoryAPI()
        rs = conn.get_attributes_ad_standard(adserver,ousearch,binduser,bindpassword,searchuser)
        print(rs)
        return jsonify(rs)
    return 'NONE'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)