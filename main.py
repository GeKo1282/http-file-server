import json, random, string, hashlib, flask, os, base64, re, mimetypes, cachetools

class SettingsJSON(dict):
    def __init__(self, *args, file_path: str = None, **kwargs):
        self.file_path = file_path
        super().__init__(*args, **kwargs)
        self.load()

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.save()

    def save(self):
        if self.file_path is not None:
            with open(self.file_path, 'w') as f:
                json.dump(self, f)

    def load(self):
        if self.file_path is not None:
            with open(self.file_path, 'r') as f:
                self.update(json.load(f))


settings = SettingsJSON(file_path='settings.json')
generate_token = lambda length: "".join([random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(length)])
hash512 = lambda string: hashlib.sha512(string.encode()).hexdigest()

app = flask.Flask(__name__, template_folder='static/html')

@cachetools.cached(cache=cachetools.TTLCache(maxsize=1, ttl=60))
def get_all_permissions(token: str, username: str, password: str, address: str = None):
    permlist = []

    for permdict in settings['access']:
        if permdict.get('address_whitelist') and not (address in permdict.get('address_whitelist', []) or any([re.match(x, address) is not None for x in permdict.get('address_whitelist', [])])):
            continue

        if permdict.get('address_blacklist') and (address in permdict.get('address_blacklist', []) or any([re.match(x, address) is not None for x in permdict.get('address_blacklist', [])])):
            continue

        if token and token in permdict.get('tokens', []):
            permlist.append(permdict)
            continue

        if username and password and {'username': username.lower(), 'password': password} in permdict.get('interactive', []):
            permlist.append(permdict)
            continue

        if permdict.get('no_auth', False):
            permlist.append(permdict)
            continue

    return permlist

def get_paths_from_permissions(permissions: list):
    paths = []

    for permission in permissions:
        for path in permission.get('filesystem_paths', []):
            paths.append(os.path.abspath(path))

    return paths

def validate_file_in_paths(file: str, paths: list):
    file = os.path.abspath(file)
    for path in paths:
        if re.match(path, file) or file.startswith(path):
            return True

    return False

def get_shortcut(name, prefix: str = None):
    for shortcut in settings['shortcuts']:
        if shortcut['name'] == name:
            return prefix + shortcut['path']


@app.route('/admin')
async def admin():
    return flask.render_template('admin.html')

@app.route('/file/<path:file>')
@app.route('/file')
async def file(file: str = "/"):
    def serve_file(file):
        def ranger(start, end, chunk_size=8192):
            with open(file, 'rb') as f:
                f.seek(int(start))
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    yield data

        mimetype = mimetypes.guess_type(file)[0]
        if mimetype is None:
            mimetype = 'text/plain'

        get_start, get_end = flask.request.headers.get('Range', 'bytes=0-').replace('bytes=', '').split('-')

        if get_end == '':
            get_end = os.path.getsize(file) - 1

        headers = {
            'Accept-Ranges': 'bytes',
            'Content-Type': mimetype,
            'Content-Length': os.path.getsize(file),
            'Content-Range': f'bytes {get_start}-{get_end}/{os.path.getsize(file)}'
        }

        return flask.Response(ranger(get_start, get_end), status=206, headers=headers, mimetype=mimetype, direct_passthrough=mimetype.startswith('video'))

    try:
        file = os.path.abspath(f"/{file}" if not file.startswith("/") else file)
    except:
        return flask.abort(403)
    
    token = flask.request.args.get('token', None)
    user = flask.request.args.get('user', None)
    user = base64.b64decode(user).decode() if user else user
    password = flask.request.args.get('password', None)
    
    permissions = get_all_permissions(token, user, password, flask.request.remote_addr)
    paths = get_paths_from_permissions(permissions)

    if not validate_file_in_paths(file, paths) and not token and not (user and password):
        return flask.render_template('interactive_login.html')
    
    if not validate_file_in_paths(file, paths):
        return flask.abort(403)

    if not os.path.exists(file):
        return flask.abort(404)
    
    if os.path.isdir(file):
        if not validate_file_in_paths(file, get_paths_from_permissions([permission for permission in permissions if permission.get('browseable', False)])):
            return flask.abort(403)
        
        directories = []
        files = []
        
        for x in os.listdir(file):
            if os.path.isdir(os.path.join(file, x)):
                directories.append(x)
                continue

            files.append({
                'name': x,
                'size': os.path.getsize(os.path.join(file, x)),
                'mimetype': mimetypes.guess_type(x)[0],
                'modified': os.path.getmtime(os.path.join(file, x)),
                'created': os.path.getctime(os.path.join(file, x))
            })

        directories.sort()
        files.sort(key=lambda x: x['name'])
        
        return flask.render_template('directory.html', directories=directories, files=files, name=os.path.basename(file) or "/")
    
    return serve_file(file)

@app.route('/<path:shortcut>')
async def shortcut(shortcut):
    target = get_shortcut(shortcut.lower(), "/file")
    if target is None:
        return flask.abort(404)
    
    return flask.redirect(target)

if __name__ == '__main__':
    app.run(host=settings.get('host', '0.0.0.0'), port=settings.get('port', 80), debug=settings.get('debug', False))