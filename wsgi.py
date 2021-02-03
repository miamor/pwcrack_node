from app import create_app

# app = create_app()
username = 'admin'
username_hash = 'admin'
app = create_app(auth_user=username, auth_hash=username_hash)
if __name__ == '__main__':
    # app.run(ssl_context=('server.crt', 'server.key'))
    base_dir = '.'
    context = (base_dir + '/server.crt', base_dir + '/server.key')
    print(base_dir + '/server.crt', base_dir + '/server.key')
    app.run(ssl_context=context, threaded=True, debug=True)
